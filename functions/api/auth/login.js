import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';

// ----- JWT helpers (no dependencies) -----
const te = new TextEncoder();
function b64urlFromBytes(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function bytesFromB64url(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function signJWT(payload, secret, expSeconds = 60 * 60 * 24 * 7) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + expSeconds, ...payload };

  const h = b64urlFromBytes(te.encode(JSON.stringify(header)));
  const p = b64urlFromBytes(te.encode(JSON.stringify(body)));
  const data = `${h}.${p}`;

  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(data));
  const s = b64urlFromBytes(new Uint8Array(sig));

  return `${data}.${s}`;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}
function cookie(name, value, { httpOnly = true, secure = true, sameSite = 'Lax', path = '/', maxAge } = {}) {
  let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
  if (httpOnly) c += '; HttpOnly';
  if (secure) c += '; Secure';
  if (typeof maxAge === 'number') c += `; Max-Age=${maxAge}`;
  return c;
}

export async function onRequestPost({ request, env }) {
  try {
    const { identifier, password } = await request.json();
    if (!identifier || !password) return json({ error: 'Missing credentials.' }, 400);

    const sql = neon(env.DATABASE_URL);
    const rows = await sql`
      SELECT user_id, login_id, name, email::text AS email, password_hash
      FROM app.users
      WHERE (login_id = ${identifier} OR email::text = ${identifier})
      LIMIT 1;
    `;
    const user = rows[0];
    if (!user) return json({ error: 'Invalid credentials.' }, 401);

    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return json({ error: 'Invalid credentials.' }, 401);

    const token = await signJWT(
      { sub: user.user_id, email: user.email, login_id: user.login_id, name: user.name },
      env.JWT_SECRET,
      60 * 60 * 24 * 7
    );

    return new Response(JSON.stringify({
      user: { user_id: user.user_id, email: user.email, login_id: user.login_id, name: user.name }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookie('rp_session', token, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: 60 * 60 * 24 * 7 })
      }
    });
  } catch (err) {
    return json({ error: 'Auth error.' }, 500);
  }
}

import { neon } from '@neondatabase/serverless';

// ---------- JWT helpers (no dependencies) ----------
const te = new TextEncoder();
function b64urlFromBytes(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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

    // Validate credentials fully in SQL using pgcrypto's crypt()
    const rows = await sql`
      SELECT user_id, login_id, name, email::text AS email
      FROM app.users
      WHERE (login_id = ${identifier} OR email::text = ${identifier})
        AND password_hash = crypt(${password}, password_hash)
      LIMIT 1;
    `;
    const user = rows[0];
    if (!user) return json({ error: 'Invalid credentials.' }, 401);

    const token = await signJWT(
      { sub: user.user_id, email: user.email, login_id: user.login_id, name: user.name },
      env.JWT_SECRET,
      60 * 60 * 24 * 7
    );

    return new Response(JSON.stringify({ user }), {
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

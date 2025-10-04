const te = new TextEncoder();
const td = new TextDecoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}
function parseCookie(str) {
  return Object.fromEntries(str.split(';').map(v => v.trim().split('=')));
}
function bytesFromB64url(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyJWT(token, secret) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) throw new Error('Malformed token');
  const data = `${h}.${p}`;

  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sigBytes = bytesFromB64url(s);
  const ok = await crypto.subtle.verify('HMAC', key, sigBytes, te.encode(data));
  if (!ok) throw new Error('Bad signature');

  const payload = JSON.parse(td.decode(bytesFromB64url(p)));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Expired');
  return payload;
}

export async function onRequestGet({ request, env }) {
  try {
    const cookies = request.headers.get('Cookie') || '';
    const token = parseCookie(cookies).rp_session;
    if (!token) return json({ error: 'Not authenticated' }, 401);

    const payload = await verifyJWT(token, env.JWT_SECRET);
    return json({ user: { user_id: payload.sub, email: payload.email, login_id: payload.login_id, name: payload.name } });
  } catch {
    return json({ error: 'Not authenticated' }, 401);
  }
}

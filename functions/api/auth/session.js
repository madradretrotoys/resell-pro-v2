import { jwtVerify } from 'jose';

export async function onRequestGet({ request, env }) {
  try {
    const cookies = request.headers.get('Cookie') || '';
    const token = parseCookie(cookies).rp_session;
    if (!token) return json({ error: 'Not authenticated' }, 401);

    const { payload } = await jwtVerify(token, new TextEncoder().encode(env.JWT_SECRET));
    return json({ user: { user_id: payload.sub, email: payload.email, login_id: payload.login_id, name: payload.name } });
  } catch {
    return json({ error: 'Not authenticated' }, 401);
  }
}

function parseCookie(str) {
  return Object.fromEntries(str.split(';').map(v => v.trim().split('=')));
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

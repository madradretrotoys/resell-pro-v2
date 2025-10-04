import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';
import { SignJWT } from 'jose';

export async function onRequestPost({ request, env }) {
  try {
    const { identifier, password } = await request.json();
    if (!identifier || !password) return json({ error: 'Missing credentials.' }, 400);

    // Connect to Neon (works in Cloudflare Workers/Pages)
    const sql = neon(env.DATABASE_URL);

    // Users table lives in the app schema; email is a domain type -> cast to text
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

    // Sign a JWT and set HttpOnly cookie (7 days)
    const token = await new SignJWT({
      sub: user.user_id,
      email: user.email,
      login_id: user.login_id,
      name: user.name
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('7d')
      .sign(new TextEncoder().encode(env.JWT_SECRET));

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

// helpers
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

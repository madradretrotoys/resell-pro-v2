// Simple client config and helpers for Resell Pro (same-origin).
// Your API should set and read HTTP-only cookies; always send credentials.

window.RP = {
  apiBase: '/', // same-origin Cloudflare routes, e.g. /api/auth/*
  // Endpoints we expect your backend to provide:
  routes: {
    login: '/api/auth/login',
    logout: '/api/auth/logout',
    session: '/api/auth/session',
    forgotPassword: '/api/auth/forgot-password',
    forgotUserId: '/api/auth/forgot-userid'
  },
  goto(path) {
    window.location.href = path;
  },
  async request(path, options = {}) {
    const res = await fetch(path, {
      method: options.method || 'GET',
      headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers || {}),
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: 'include' // send cookies for auth
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON */ }
    return { ok: res.ok, status: res.status, data };
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();
});

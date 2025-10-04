(async function () {
  // Only runs on pages that include it (dashboard)
  const { ok, data } = await RP.request(RP.routes.session);
  if (!ok || !data || !data.user) {
    // Not authenticated: go to sign in
    RP.goto('/index.html');
    return;
  }

  // Populate basic user info if provided by backend
  const u = data.user || {};
  const byId = (id) => document.getElementById(id);
  const map = [
    ['u-name', u.name || '—'],
    ['u-email', u.email || '—'],
    ['u-login', u.login_id || '—'],
    ['u-tenant', (u.tenant && (u.tenant.name || u.tenant.slug)) || '—'],
    ['u-role', u.role || '—']
  ];
  map.forEach(([id, val]) => { const el = byId(id); if (el) el.textContent = val; });

  // Logout
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await RP.request(RP.routes.logout, { method: 'POST' });
      RP.goto('/index.html');
    });
  }
})();

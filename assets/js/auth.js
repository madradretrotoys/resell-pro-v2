(function () {
  const form = document.getElementById('signin-form');
  const userid = document.getElementById('userid');
  const password = document.getElementById('password');
  const err = document.getElementById('form-error');
  const submit = document.getElementById('signin-submit');
  const toggleBtn = document.getElementById('togglePassword');

  if (toggleBtn && password) {
    toggleBtn.addEventListener('click', () => {
      const isHidden = password.type === 'password';
      password.type = isHidden ? 'text' : 'password';
      toggleBtn.textContent = isHidden ? 'Hide' : 'Show';
      toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
      password.focus({ preventScroll: true });
    });
  }

  function showError(message) {
    if (!err) return;
    err.textContent = message || 'Something went wrong.';
    err.hidden = false;
  }
  function clearError() {
    if (!err) return;
    err.textContent = '';
    err.hidden = true;
  }

  async function checkSessionAndRedirect() {
    const { ok, data } = await RP.request(RP.routes.session);
    if (ok && data && data.user) {
      RP.goto('/screens/dashboard.html');
    }
  }
  checkSessionAndRedirect();

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearError();

      const id = (userid.value || '').trim();
      const pwd = password.value || '';

      if (!id || !pwd) {
        showError('Please enter your User ID or Email and your password.');
        return;
      }

      submit.disabled = true;
      submit.textContent = 'Signing in…';

      const { ok, status, data } = await RP.request(RP.routes.login, {
        method: 'POST',
        body: { identifier: id, password: pwd }
      });

      submit.disabled = false;
      submit.textContent = 'Sign In';

      if (ok) {
        RP.goto('/screens/dashboard.html');
      } else {
        const msg = (data && data.error) || (status === 401 ? 'Invalid credentials.' : 'Unable to sign in.');
        showError(msg);
      }
    });
  }
})();

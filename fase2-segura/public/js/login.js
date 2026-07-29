document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const msg = document.getElementById('msg');
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    msg.textContent = data.message || data.error;
    if (res.ok) {
      window.location.href = '/notes';
    }
  } catch (err) {
    msg.textContent = 'Error de conexion: ' + err.message;
  }
});

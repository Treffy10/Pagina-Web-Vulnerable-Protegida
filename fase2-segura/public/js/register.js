document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const msg = document.getElementById('msg');
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (res.ok) {
      msg.style.color = '#34d399';
      msg.textContent = 'Cuenta creada, ya puedes iniciar sesion.';
      setTimeout(() => { window.location.href = '/login'; }, 1200);
    } else {
      msg.style.color = '#f87171';
      msg.textContent = data.error || 'No se pudo registrar el usuario';
    }
  } catch (err) {
    msg.style.color = '#f87171';
    msg.textContent = 'Error de conexion: ' + err.message;
  }
});

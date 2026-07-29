async function loadSession() {
  const el = document.getElementById('sessionUser');
  try {
    const res = await fetch('/api/auth/me', { credentials: 'include' });
    if (res.status === 401) {
      window.location.href = '/login';
      return;
    }
    const data = await res.json();
    el.textContent = data.user.username;
  } catch (err) {
    el.textContent = 'desconocido';
  }
}

async function loadNotes() {
  const body = document.getElementById('notesBody');
  try {
    const res = await fetch('/api/notes', { credentials: 'include' });
    if (res.status === 401) {
      window.location.href = '/login';
      return;
    }
    const notes = res.ok ? await res.json() : [];
    body.innerHTML = notes.map((n) => {
      const fileLink = n.file_path
        ? `<a class="file-link" href="/api/files/${n.id}" target="_blank" rel="noopener">archivo</a>`
        : '-';
      return `<tr>
        <td>${n.id}</td>
        <td>${n.title}</td>
        <td>${n.content}</td>
        <td>${fileLink}</td>
        <td class="actions-inline"><button data-id="${n.id}" class="delete-btn">Eliminar</button></td>
      </tr>`;
    }).join('') || '<tr><td colspan="5">Sin notas todavia</td></tr>';

    body.querySelectorAll('.delete-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        await fetch(`/api/notes/${btn.dataset.id}`, { method: 'DELETE', credentials: 'include' });
        loadNotes();
      });
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5">Error cargando notas: ${err.message}</td></tr>`;
  }
}

document.getElementById('noteForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData();
  fd.append('title', document.getElementById('title').value);
  fd.append('content', document.getElementById('content').value);
  const fileInput = document.getElementById('file');
  if (fileInput.files[0]) fd.append('file', fileInput.files[0]);
  await fetch('/api/notes', { method: 'POST', credentials: 'include', body: fd });
  fileInput.value = '';
  document.getElementById('title').value = '';
  document.getElementById('content').value = '';
  loadNotes();
});

document.getElementById('logoutLink').addEventListener('click', async (e) => {
  e.preventDefault();
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
  window.location.href = '/login';
});

loadSession();
loadNotes();

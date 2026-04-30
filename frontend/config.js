// PhishGuard — API Configuration
// This file connects your frontend to your own Python Flask backend

const API_URL = 'http://127.0.0.1:5000/api';

// ── Core fetch helper ──────────────────────────────────────────────────────
async function apiFetch(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };

  const token = localStorage.getItem('pg_token');
  if (token) options.headers['Authorization'] = `Bearer ${token}`;
  if (body) options.body = JSON.stringify(body);

  const response = await fetch(`${API_URL}/${endpoint}`, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'API error');
  return data;
}

// ── Auth helpers ───────────────────────────────────────────────────────────
function saveSession(data) {
  localStorage.setItem('pg_token', data.token);
  localStorage.setItem('pg_user',  JSON.stringify(data.user));
}

function getUser() {
  const u = localStorage.getItem('pg_user');
  return u ? JSON.parse(u) : null;
}

function clearSession() {
  localStorage.removeItem('pg_token');
  localStorage.removeItem('pg_user');
}

function requireAuth(role = null) {
  const user = getUser();
  if (!user) { window.location.href = 'login.html'; return null; }
  if (role && user.role !== role) {
    window.location.href = user.role === 'admin'
      ? 'admin-dashboard.html'
      : 'awareness-training.html';
    return null;
  }
  return user;
}

// ── Toast notification helper ──────────────────────────────────────────────
function showToast(message, type = 'success') {
  const existing = document.getElementById('pgToast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.id = 'pgToast';
  toast.style.cssText = `
    position:fixed;top:20px;right:20px;z-index:9999;
    padding:14px 20px;border-radius:10px;
    font-family:'Syne',sans-serif;font-size:0.85rem;font-weight:600;
    max-width:360px;box-shadow:0 8px 24px rgba(0,0,0,0.4);
    animation:fadeUp 0.3s ease;
    background:${type==='success'?'#00e5a015':'#ff456015'};
    border:1px solid ${type==='success'?'#00e5a040':'#ff456040'};
    color:${type==='success'?'#00e5a0':'#ff4560'};
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast?.remove(), 4000);
}

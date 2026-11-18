const api = globalThis.browser ?? globalThis.chrome;

const status = document.getElementById('status');
document.getElementById('version').textContent = `v${api.runtime.getManifest().version_name ?? api.runtime.getManifest().version}`;

const result = await api.runtime.sendMessage({ type: 'status' });
if (result?.connected) {
  status.textContent = 'Connected to the PhylaxBox desktop app.';
  status.className = 'ok';
} else {
  status.textContent = 'The PhylaxBox desktop app is not running or not installed.';
  status.className = 'warn';
}

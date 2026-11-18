// PhylaxBox extension background (spec §8).
// The extension never decrypts or stores the vault: every request goes to the
// desktop app through the native messaging host (spec §8.3, §9).

const api = globalThis.browser ?? globalThis.chrome;
export const NATIVE_HOST = 'com.phylaxbox.native_host';

async function desktopStatus() {
  try {
    const reply = await api.runtime.sendNativeMessage(NATIVE_HOST, { type: 'ping', version: 1 });
    return { connected: true, reply };
  } catch (error) {
    return { connected: false, error: String(error?.message ?? error) };
  }
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only the extension's own pages may talk to the background.
  if (sender.id !== api.runtime.id || sender.tab) return false;
  if (message?.type === 'status') {
    desktopStatus().then(sendResponse);
    return true; // async response
  }
  return false;
});

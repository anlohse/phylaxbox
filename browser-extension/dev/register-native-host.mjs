// Registers a locally built native messaging host for the current user, to
// try the extension unpacked without installing PhylaxBox. The installers
// do the same system-wide.
//
//   node dev/register-native-host.mjs <path to phylaxbox-native-host[.exe]>
//   node dev/register-native-host.mjs --remove
//
// Windows: manifests in %LOCALAPPDATA%\PhylaxBox\native-messaging, registry
//          keys under HKCU\Software\{Google\Chrome,Microsoft\Edge,Chromium,Mozilla}.
// Linux:   manifests in the per-user NativeMessagingHosts directories of
//          Chrome, Chromium, Edge, Brave and Firefox.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const NAME = 'com.phylaxbox.native_host';
const here = dirname(fileURLToPath(import.meta.url));
const ids = JSON.parse(readFileSync(join(here, '..', 'extension-ids.json'), 'utf8'));

const args = process.argv.slice(2);
const remove = args.includes('--remove');
const hostArg = args.find((a) => !a.startsWith('--'));
if (!remove && !hostArg) {
  console.error('usage: node dev/register-native-host.mjs <path to phylaxbox-native-host> | --remove');
  process.exit(2);
}
const host = hostArg ? resolve(hostArg) : '';
if (!remove && !existsSync(host)) {
  console.error(`not found: ${host}`);
  process.exit(1);
}

const manifest = (flavor) => JSON.stringify({
  name: NAME,
  description: 'PhylaxBox native messaging host (development build)',
  path: host,
  type: 'stdio',
  ...(flavor === 'chromium'
    ? { allowed_origins: ids.chrome.ids.map((id) => `chrome-extension://${id}/`) }
    : { allowed_extensions: ids.firefox.ids }),
}, null, 2) + '\n';

if (process.platform === 'win32') {
  const dir = join(process.env.LOCALAPPDATA, 'PhylaxBox', 'native-messaging');
  const keys = [['Google\\Chrome', 'chromium'], ['Microsoft\\Edge', 'chromium'], ['Chromium', 'chromium'], ['Mozilla', 'firefox']];
  if (!remove) {
    mkdirSync(dir, { recursive: true });
    for (const flavor of ['chromium', 'firefox']) writeFileSync(join(dir, `${NAME}.${flavor}.json`), manifest(flavor));
  }
  for (const [vendor, flavor] of keys) {
    const key = `HKCU\\Software\\${vendor}\\NativeMessagingHosts\\${NAME}`;
    if (remove) {
      try { execFileSync('reg', ['delete', key, '/f'], { stdio: 'ignore' }); } catch { /* not there */ }
    } else {
      execFileSync('reg', ['add', key, '/ve', '/t', 'REG_SZ', '/d', join(dir, `${NAME}.${flavor}.json`), '/f'], { stdio: 'ignore' });
      console.log(`${key} -> ${NAME}.${flavor}.json`);
    }
  }
  if (remove) rmSync(dir, { recursive: true, force: true });
} else {
  const config = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  const targets = [
    [join(config, 'google-chrome', 'NativeMessagingHosts'), 'chromium'],
    [join(config, 'chromium', 'NativeMessagingHosts'), 'chromium'],
    [join(config, 'microsoft-edge', 'NativeMessagingHosts'), 'chromium'],
    [join(config, 'BraveSoftware', 'Brave-Browser', 'NativeMessagingHosts'), 'chromium'],
    [join(homedir(), '.mozilla', 'native-messaging-hosts'), 'firefox'],
  ];
  for (const [dir, flavor] of targets) {
    const file = join(dir, `${NAME}.json`);
    if (remove) {
      rmSync(file, { force: true });
    } else {
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, manifest(flavor));
      console.log(file);
    }
  }
}
console.log(remove ? 'Removed.' : `Registered ${host}`);

// Builds the PhylaxBox browser extension for Chromium (Chrome/Edge) and Firefox.
//
//   node build.mjs [--version 1.2.3[-suffix]] [--out dist] [--zip]
//
// Output: <out>/chrome/, <out>/firefox/ and, with --zip,
// <out>/phylaxbox-extension-<browser>-<version>.zip (deterministic archives:
// sorted entries, fixed timestamps). No dependencies beyond Node >= 22.
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, deflateRawSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const BROWSERS = ['chrome', 'firefox'];

function parseArgs(argv) {
  const args = { version: '0.0.0-dev', out: join(here, 'dist'), zip: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--version') args.version = argv[++i];
    else if (argv[i] === '--out') args.out = resolve(argv[++i]);
    else if (argv[i] === '--zip') args.zip = true;
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  return args;
}

function listFiles(dir) {
  return readdirSync(dir, { recursive: true })
    .map((p) => join(dir, p))
    .filter((p) => statSync(p).isFile())
    .sort();
}

function buildManifest(browser, version) {
  const match = /^(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$/.exec(version);
  if (!match) throw new Error(`version '${version}' is not MAJOR.MINOR.PATCH[-suffix]`);
  const base = JSON.parse(readFileSync(join(here, 'manifests', 'base.json'), 'utf8'));
  const specific = JSON.parse(readFileSync(join(here, 'manifests', `${browser}.json`), 'utf8'));
  // Stores accept only dot-separated integers in "version".
  const manifest = { ...base, ...specific, version: match[1] };
  if (browser === 'chrome' && match[2]) manifest.version_name = version;
  return manifest;
}

// Minimal ZIP writer (deflate, UTF-8 names, fixed 1980-01-01 timestamps).
function zip(files) {
  const DOS_TIME = 0;
  const DOS_DATE = (0 << 9) | (1 << 5) | 1;
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of files) {
    const nameBuf = Buffer.from(name, 'utf8');
    const compressed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBuf, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + compressed.length;
  }
  const centralSize = centrals.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

const args = parseArgs(process.argv.slice(2));
const srcDir = join(here, 'src');
for (const browser of BROWSERS) {
  const outDir = join(args.out, browser);
  rmSync(outDir, { recursive: true, force: true });
  const entries = [];
  for (const file of listFiles(srcDir)) {
    const rel = relative(srcDir, file).split(sep).join('/');
    mkdirSync(dirname(join(outDir, rel)), { recursive: true });
    copyFileSync(file, join(outDir, rel));
    entries.push({ name: rel, data: readFileSync(file) });
  }
  const manifest = JSON.stringify(buildManifest(browser, args.version), null, 2) + '\n';
  writeFileSync(join(outDir, 'manifest.json'), manifest);
  entries.push({ name: 'manifest.json', data: Buffer.from(manifest) });
  entries.sort((a, b) => (a.name < b.name ? -1 : 1));

  if (args.zip) {
    const zipPath = join(args.out, `phylaxbox-extension-${browser}-${args.version}.zip`);
    writeFileSync(zipPath, zip(entries));
    console.log(zipPath);
  } else {
    console.log(outDir);
  }
}

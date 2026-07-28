#!/usr/bin/env node
//
// Переносит установку 1.x на credential envelope 2.0.
//
// Берёт старые keypair.json + device.json из корня проекта и живую сессию Kaspi
// (tokenSN + vtokenSecret из localStorage браузера) и печатает готовый конверт.
// Устройство при этом сохраняется, поэтому повторный вход по SMS не нужен и
// сессия не вытесняется.
//
//   npm run mint-credentials -- --token-sn TSN --vtoken-secret BASE64
//   npm run mint-credentials -- --from-session ./session.json
//
// session.json — то, что лежит в localStorage['kaspi_session'] версии 1.x.

import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');

const parseArgs = () => {
  const out = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
};

const fail = (msg) => {
  console.error(`\n✖ ${msg}\n`);
  process.exit(1);
};

const args = parseArgs();

if (args.help) {
  console.log(`
Usage:
  npm run mint-credentials -- --token-sn <TSN> --vtoken-secret <BASE64> [--profile-id N]
  npm run mint-credentials -- --from-session <path/to/session.json>

Options:
  --token-sn        tokenSN из старой сессии
  --vtoken-secret   vtokenSecret из старой сессии (зашифрован TOKEN_SECRET_KEY)
  --profile-id      profileId (необязательно)
  --org-name        название организации (необязательно)
  --phone           номер телефона (необязательно)
  --from-session    JSON-файл с полями tokenSN/vtokenSecret/profileId/orgName/phoneNumber
  --device          путь к device.json (по умолчанию ./device.json)
  --keypair         путь к keypair.json (по умолчанию ./keypair.json)
`);
  process.exit(0);
}

if (!process.env.TOKEN_SECRET_KEYS && !process.env.TOKEN_SECRET_KEY) {
  fail('TOKEN_SECRET_KEY is not set — it is needed to decrypt the old vtokenSecret.');
}

// Импортируем после проверки ключа: crypto.js завершает процесс, если его нет.
const { decryptSecret } = await import('../src/crypto.js');
const { sealCredentials } = await import('../src/envelope.js');

const keypairFile = args.keypair || path.join(ROOT_DIR, 'keypair.json');
const deviceFile = args.device || path.join(ROOT_DIR, 'device.json');

if (!fs.existsSync(keypairFile)) fail(`Not found: ${keypairFile}\nNothing to migrate — just onboard through /api/auth/init.`);
if (!fs.existsSync(deviceFile)) fail(`Not found: ${deviceFile}`);

const keypair = JSON.parse(fs.readFileSync(keypairFile, 'utf8'));
const { deviceId, installId, pinHash } = JSON.parse(fs.readFileSync(deviceFile, 'utf8'));

if (!keypair.privateKey) fail(`${keypairFile} has no privateKey field.`);
if (!deviceId || !installId || !pinHash) fail(`${deviceFile} is missing deviceId/installId/pinHash.`);

let src = {};
if (args.fromSession) {
  if (!fs.existsSync(args.fromSession)) fail(`Not found: ${args.fromSession}`);
  src = JSON.parse(fs.readFileSync(args.fromSession, 'utf8'));
}

const tokenSN = args.tokenSn || src.tokenSN;
const vtokenSecret = args.vtokenSecret || src.vtokenSecret;

if (!tokenSN || !vtokenSecret) {
  fail(
    'tokenSN and vtokenSecret are required.\n' +
      "  Open the 1.x web UI, run localStorage.getItem('kaspi_session') in the browser console,\n" +
      '  save it to a file and pass --from-session <file>.',
  );
}

let rawSecret;
try {
  rawSecret = decryptSecret(vtokenSecret);
} catch {
  fail('vtokenSecret could not be decrypted — TOKEN_SECRET_KEY does not match the one that issued it.');
}

const credentials = sealCredentials({
  device: {
    deviceId,
    installId,
    pinHash,
    privateKey: keypair.privateKey,
  },
  session: {
    tokenSN,
    secret: rawSecret.toString('base64'),
    profileId: args.profileId ? Number(args.profileId) : (src.profileId ?? null),
    organizationId: src.organizationId ?? null,
    orgName: args.orgName || src.orgName || null,
    phoneNumber: args.phone || src.phoneNumber || src.phone || null,
  },
});

console.log(`
─────────────────────────────────────────────────────────────
 Credential envelope (X-Kaspi-Credentials)
─────────────────────────────────────────────────────────────
 deviceId : ${deviceId}
 tokenSN  : ${tokenSN}
 org      : ${args.orgName || src.orgName || '—'}

${credentials}

 Храните его как пароль: он даёт полный доступ к этому мерчанту.
 Передавайте только по TLS.

 Дальше:
   1. Сохраните конверт в своём бэкенде рядом с записью мерчанта.
   2. Проверьте: curl -H "X-Kaspi-Credentials: <конверт>" localhost:3000/api/session/check
   3. Переименуйте keypair.json / device.json в *.migrated.
─────────────────────────────────────────────────────────────
`);

import crypto from 'crypto';

const vtokenSuite = 'OCRA-1:HOTP-SHA256-6:QH64-T1M';

// ─── AES-256-GCM encryption for credential envelopes and vtokenSecret ───
//
// TOKEN_SECRET_KEYS is a comma-separated list of 32-byte hex keys. The first
// one encrypts; every one is tried on decrypt, so a key can be rotated without
// invalidating envelopes already held by clients. TOKEN_SECRET_KEY (singular)
// is still accepted as a single-key alias.

const parseKeys = () => {
  const raw = process.env.TOKEN_SECRET_KEYS || process.env.TOKEN_SECRET_KEY || '';
  return raw
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k, i) => {
      if (!/^[0-9a-fA-F]{64}$/.test(k)) {
        console.error(`FATAL: TOKEN_SECRET_KEYS[${i}] is not a 64-character hex string.`);
        process.exit(1);
      }
      return Buffer.from(k, 'hex');
    });
};

const ENCRYPTION_KEYS = parseKeys();

if (ENCRYPTION_KEYS.length === 0) {
  console.error('FATAL: TOKEN_SECRET_KEYS (or TOKEN_SECRET_KEY) environment variable is not set.');
  console.error('Generate one with: echo "TOKEN_SECRET_KEY=$(openssl rand -hex 32)" > .env');
  process.exit(1);
}

export const encryptSecret = (secretBuffer) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEYS[0], iv);
  const encrypted = Buffer.concat([cipher.update(secretBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
};

/**
 * Расшифровывает, перебирая все настроенные ключи.
 * Возвращает {plaintext, keyIndex} — keyIndex > 0 означает, что значение
 * зашифровано устаревшим ключом и его следует перевыпустить.
 */
export const decryptSecretWithKeyIndex = (tokenB64) => {
  const buf = Buffer.from(tokenB64, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);

  let lastErr;
  for (let i = 0; i < ENCRYPTION_KEYS.length; i++) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEYS[i], iv);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return { plaintext, keyIndex: i };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Decryption failed');
};

export const decryptSecret = (tokenB64) => decryptSecretWithKeyIndex(tokenB64).plaintext;

// ─── ECDH (stateless — the keypair lives in a local during a single sign-in) ───

export const generateEcdhKeyPair = () => crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});

export const ecdhPublicKeyB64 = (keyPair) =>
  keyPair.publicKey.export({type: 'spki', format: 'der'}).toString('base64');

export const deriveSharedSecret = (privateKey, serverX509B64) =>
  crypto.diffieHellman({
    privateKey,
    publicKey: crypto.createPublicKey({
      key: Buffer.from(serverX509B64, 'base64'),
      format: 'der',
      type: 'spki',
    }),
  });

// ─── Helpers ───

const hexToBytes = (hex) => {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return Buffer.from(bytes);
};

// ─── OCRA-1 TOTP (matches Kaspi vtoken) ───

export const computeTokenSnMac = (tokenSN, secret) => {
  if (!secret) return '000000';

  const timeStep = BigInt(Date.now()) / BigInt(30000);
  const timeHex = timeStep.toString(16);

  const qHex = Buffer.from(tokenSN || '00000000')
    .toString('hex')
    .substring(0, 64);

  const suiteBytes = Buffer.from(vtokenSuite);
  const separator = Buffer.from([0x00]);

  const qPadded = qHex.padEnd(256, '0');
  const qBytes = hexToBytes(qPadded);

  const tPadded = timeHex.padStart(16, '0');
  const tBytes = hexToBytes(tPadded);

  const dataBuffer = Buffer.concat([suiteBytes, separator, qBytes, tBytes]);

  const hash = crypto.createHmac('sha256', secret).update(dataBuffer).digest();

  // Dynamic truncation (RFC 4226)
  const offset = hash[hash.length - 1] & 0x0f;
  const binCode =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return (binCode % 1000000).toString().padStart(6, '0');
};

// ─── ECDSA signing ───

export const ecSign = (data, privateKey) => {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey).toString('base64');
};

export const signDataPayload = (dataB64, privateKey) => ecSign(dataB64, privateKey);

export const computeXSU = (url) => crypto.createHash('md5').update(url.toLowerCase()).digest('hex');

export const computeXSign = (url, headers, xshList, body, privateKey) => {
  const keys = xshList.split(',');
  const lines = [];
  for (const name of keys) {
    if (name === 'url') {
      lines.push('url:' + url.toLowerCase());
    } else {
      lines.push(name.toLowerCase() + ':' + (headers[name] || ''));
    }
  }
  let signText = lines.join('\n');
  if (body) {
    signText += '\n' + body;
  }
  const hash = crypto.createHash('sha256').update(signText, 'utf8').digest();
  return ecSign(hash, privateKey);
};

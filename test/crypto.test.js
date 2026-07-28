import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

// Set TOKEN_SECRET_KEY before importing crypto module
process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const {
  encryptSecret,
  decryptSecret,
  computeTokenSnMac,
  computeXSU,
  ecSign,
  computeXSign,
  generateEcdhKeyPair,
  ecdhPublicKeyB64,
  deriveSharedSecret,
} = await import('../src/crypto.js');

const newKey = () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

const verify = (data, sigB64, publicKey) => {
  const v = crypto.createVerify('SHA256');
  v.update(data);
  v.end();
  return v.verify(publicKey, Buffer.from(sigB64, 'base64'));
};

describe('encryptSecret / decryptSecret', () => {
  it('should round-trip a secret buffer', () => {
    const original = Buffer.from('my-super-secret-value');
    const encrypted = encryptSecret(original);
    const decrypted = decryptSecret(encrypted);
    assert.deepStrictEqual(decrypted, original);
  });

  it('should produce different ciphertexts for the same input (random IV)', () => {
    const original = Buffer.from('test');
    const a = encryptSecret(original);
    const b = encryptSecret(original);
    assert.notEqual(a, b);
  });

  it('should fail to decrypt tampered data', () => {
    const encrypted = encryptSecret(Buffer.from('secret'));
    const buf = Buffer.from(encrypted, 'base64');
    buf[20] ^= 0xff; // tamper with ciphertext
    assert.throws(() => decryptSecret(buf.toString('base64')));
  });
});

describe('computeTokenSnMac', () => {
  it('should return 6-digit string', () => {
    const secret = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
    const result = computeTokenSnMac('TSN12345', secret);
    assert.match(result, /^\d{6}$/);
  });

  it('should return 000000 when secret is null', () => {
    const result = computeTokenSnMac('TSN12345', null);
    assert.equal(result, '000000');
  });
});

describe('computeXSU', () => {
  it('should return md5 hex of lowercased url', () => {
    const result = computeXSU('https://example.com/Path');
    assert.match(result, /^[0-9a-f]{32}$/);
  });

  it('should be case-insensitive', () => {
    const a = computeXSU('HTTPS://EXAMPLE.COM');
    const b = computeXSU('https://example.com');
    assert.equal(a, b);
  });
});

describe('ecSign', () => {
  it('should produce a signature verifiable with the matching public key', () => {
    const kp = newKey();
    assert.ok(verify('hello', ecSign('hello', kp.privateKey), kp.publicKey));
  });

  it('should produce different signatures for different keys (no global key leaks in)', () => {
    const a = newKey();
    const b = newKey();
    assert.notEqual(ecSign('same-data', a.privateKey), ecSign('same-data', b.privateKey));
    assert.ok(!verify('same-data', ecSign('same-data', a.privateKey), b.publicKey));
  });
});

describe('computeXSign canonical string', () => {
  const kp = newKey();
  const url = 'https://QrPay.kaspi.kz/v01/Qr-Token/Create';
  const xsh = 'url,X-Install-ID,X-Time,X-Call';
  const headers = {
    'X-Install-ID': 'INSTALL-1',
    'X-Time': '2026-07-28T10:00:00.000+0500',
    'X-Call': 'notConnected',
  };
  const body = '{"PaymentAmount":100}';

  const digestOf = (text) => crypto.createHash('sha256').update(text, 'utf8').digest();

  it('signs sha256 of "name:value" lines joined by \\n, url lowercased, body appended', () => {
    const expected =
      `url:${url.toLowerCase()}\n` +
      `x-install-id:INSTALL-1\n` +
      `x-time:2026-07-28T10:00:00.000+0500\n` +
      `x-call:notConnected\n` +
      body;
    const sig = computeXSign(url, headers, xsh, body, kp.privateKey);
    assert.ok(verify(digestOf(expected), sig, kp.publicKey));
  });

  it('omits the trailing body line when there is no body', () => {
    const expected =
      `url:${url.toLowerCase()}\n` +
      `x-install-id:INSTALL-1\n` +
      `x-time:2026-07-28T10:00:00.000+0500\n` +
      `x-call:notConnected`;
    const sig = computeXSign(url, headers, xsh, undefined, kp.privateKey);
    assert.ok(verify(digestOf(expected), sig, kp.publicKey));
  });

  it('renders a header listed in X-SH but absent from headers as an empty value', () => {
    const expected = `url:${url.toLowerCase()}\nx-missing:`;
    const sig = computeXSign(url, {}, 'url,X-Missing', undefined, kp.privateKey);
    assert.ok(verify(digestOf(expected), sig, kp.publicKey));
  });

  it('changes the signature when only the body changes (regression guard for 468668e)', () => {
    const a = computeXSign(url, headers, xsh, '{"PaymentAmount":100}', kp.privateKey);
    const b = computeXSign(url, headers, xsh, '{"PaymentAmount":200}', kp.privateKey);
    assert.notEqual(a, b);
  });
});

describe('ECDH', () => {
  it('should derive the same shared secret from both sides', () => {
    const client = generateEcdhKeyPair();
    const server = generateEcdhKeyPair();

    const clientSide = deriveSharedSecret(client.privateKey, ecdhPublicKeyB64(server));
    const serverSide = deriveSharedSecret(server.privateKey, ecdhPublicKeyB64(client));

    assert.equal(clientSide.length, 32);
    assert.deepEqual(clientSide, serverSide);
  });

  it('should derive different secrets for independent keypairs (no shared singleton)', () => {
    const server = generateEcdhKeyPair();
    const a = deriveSharedSecret(generateEcdhKeyPair().privateKey, ecdhPublicKeyB64(server));
    const b = deriveSharedSecret(generateEcdhKeyPair().privateKey, ecdhPublicKeyB64(server));
    assert.notDeepEqual(a, b);
  });
});

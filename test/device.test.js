import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { createDeviceIdentity, importPrivateKey, derivePublicMaterial, buildDevice } = await import(
  '../src/device.js'
);

describe('createDeviceIdentity', () => {
  it('should mint uppercase UUIDs, an md5 pinHash and a P-256 private key', () => {
    const d = createDeviceIdentity();
    assert.match(d.deviceId, /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/);
    assert.match(d.installId, /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/);
    assert.match(d.pinHash, /^[0-9a-f]{32}$/);

    const key = importPrivateKey(d.privateKey);
    assert.equal(key.asymmetricKeyType, 'ec');
    assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
  });

  it('should mint a distinct identity every time', () => {
    const a = createDeviceIdentity();
    const b = createDeviceIdentity();
    assert.notEqual(a.deviceId, b.deviceId);
    assert.notEqual(a.installId, b.installId);
    assert.notEqual(a.pinHash, b.pinHash);
    assert.notEqual(a.privateKey, b.privateKey);
  });
});

describe('derivePublicMaterial', () => {
  it('should produce a 65-byte uncompressed EC point starting with 0x04', () => {
    const { pk } = derivePublicMaterial(importPrivateKey(createDeviceIdentity().privateKey));
    const raw = Buffer.from(pk, 'base64');
    assert.equal(raw.length, 65);
    assert.equal(raw[0], 0x04);
  });

  it('should set pkTag to the md5 of pk', () => {
    const { pk, pkTag } = derivePublicMaterial(importPrivateKey(createDeviceIdentity().privateKey));
    assert.equal(pkTag, crypto.createHash('md5').update(pk).digest('hex'));
  });

  it('should produce an x509 that re-imports as a public key', () => {
    const { x509 } = derivePublicMaterial(importPrivateKey(createDeviceIdentity().privateKey));
    const pub = crypto.createPublicKey({ key: Buffer.from(x509, 'base64'), format: 'der', type: 'spki' });
    assert.equal(pub.asymmetricKeyType, 'ec');
  });

  // Pins the derivation lifted from the old src/config.js:37-41. If this drifts,
  // Kaspi rejects every signed request with an opaque error.
  it('should match the legacy config.js derivation for the same key', () => {
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const legacyDer = kp.publicKey.export({ type: 'spki', format: 'der' });
    const legacyX509 = legacyDer.toString('base64');
    const legacyPk = legacyDer.slice(legacyDer.length - 65).toString('base64');
    const legacyPkTag = crypto.createHash('md5').update(legacyPk).digest('hex');

    const derived = derivePublicMaterial(kp.privateKey);
    assert.equal(derived.x509, legacyX509);
    assert.equal(derived.pk, legacyPk);
    assert.equal(derived.pkTag, legacyPkTag);
  });
});

describe('buildDevice', () => {
  it('should expand a stored identity into a signing-ready device', () => {
    const stored = createDeviceIdentity();
    const device = buildDevice(stored);

    assert.equal(device.deviceId, stored.deviceId);
    assert.equal(device.installId, stored.installId);
    assert.equal(device.pinHash, stored.pinHash);
    assert.equal(device.privateKey.asymmetricKeyType, 'ec');
    assert.match(device.pkTag, /^[0-9a-f]{32}$/);
    assert.equal(Buffer.from(device.pk, 'base64').length, 65);
  });

  it('should round-trip through JSON (the envelope path)', () => {
    const stored = createDeviceIdentity();
    const a = buildDevice(stored);
    const b = buildDevice(JSON.parse(JSON.stringify(stored)));
    assert.equal(a.pk, b.pk);
    assert.equal(a.pkTag, b.pkTag);
    assert.equal(a.x509, b.x509);
  });
});

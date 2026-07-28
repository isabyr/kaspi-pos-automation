// Ротация TOKEN_SECRET_KEYS проверяется в отдельном файле: ключи читаются один
// раз при импорте src/crypto.js, поэтому окружение должно быть выставлено до
// любого импорта. Конверт под старым ключом собирается вручную — это заодно
// фиксирует формат на проводе (iv || tag || ciphertext, base64).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

const OLD_KEY = 'c'.repeat(64);
const NEW_KEY = 'd'.repeat(64);

process.env.TOKEN_SECRET_KEYS = `${NEW_KEY},${OLD_KEY}`;

const { createDeviceIdentity } = await import('../src/device.js');
const { unsealCredentials } = await import('../src/envelope.js');

const sealWith = (hexKey, payload) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(hexKey, 'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
};

const device = createDeviceIdentity();
const payload = {
  v: 1,
  typ: 'kaspi.credentials',
  device,
  session: {
    tokenSN: 'TSN-ROTATE',
    secret: crypto.randomBytes(32).toString('base64'),
    profileId: 7,
    organizationId: 1,
    orgName: 'Org',
    phoneNumber: '7010000000',
  },
  app: {},
  iat: new Date().toISOString(),
};

describe('TOKEN_SECRET_KEYS rotation', () => {
  it('should unseal an envelope encrypted with a retired key', () => {
    const ctx = unsealCredentials(sealWith(OLD_KEY, payload));
    assert.equal(ctx.tokenSN, 'TSN-ROTATE');
    assert.equal(ctx.device.deviceId, device.deviceId);
  });

  it('should hand back a re-sealed envelope for a retired key', () => {
    const ctx = unsealCredentials(sealWith(OLD_KEY, payload));
    assert.ok(ctx.resealed, 'expected a refreshed envelope');
    assert.notEqual(ctx.resealed, sealWith(OLD_KEY, payload));
  });

  it('should produce a refreshed envelope that no longer needs rotation', () => {
    const first = unsealCredentials(sealWith(OLD_KEY, payload));
    const second = unsealCredentials(first.resealed);

    assert.equal(second.tokenSN, 'TSN-ROTATE');
    assert.equal(second.device.deviceId, device.deviceId);
    assert.equal(second.device.pk, first.device.pk);
    assert.equal(second.resealed, null, 'already on the primary key');
  });

  it('should not re-seal an envelope already using the primary key', () => {
    const ctx = unsealCredentials(sealWith(NEW_KEY, payload));
    assert.equal(ctx.resealed, null);
  });

  it('should still reject an envelope under an unknown key', () => {
    assert.throws(() => unsealCredentials(sealWith('e'.repeat(64), payload)), {
      code: 'invalid_credentials',
    });
  });
});

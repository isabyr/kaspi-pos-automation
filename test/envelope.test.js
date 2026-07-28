import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

const KEY_A = 'a'.repeat(64);

process.env.TOKEN_SECRET_KEY = KEY_A;

const { createDeviceIdentity } = await import('../src/device.js');
const {
  sealCredentials,
  unsealCredentials,
  sealOnboarding,
  unsealOnboarding,
  ONBOARDING_TTL_MS,
} = await import('../src/envelope.js');
const { encryptSecret } = await import('../src/crypto.js');

const device = createDeviceIdentity();
const session = {
  tokenSN: 'TSN-123',
  secret: crypto.randomBytes(32).toString('base64'),
  profileId: 42,
  organizationId: 777,
  orgName: 'ТОО Ромашка',
  phoneNumber: '7011234567',
};

describe('credential envelope', () => {
  it('should round-trip device, key and session', () => {
    const ctx = unsealCredentials(sealCredentials({ device, session }));

    assert.equal(ctx.device.deviceId, device.deviceId);
    assert.equal(ctx.device.installId, device.installId);
    assert.equal(ctx.device.pinHash, device.pinHash);
    assert.equal(ctx.tokenSN, 'TSN-123');
    assert.equal(ctx.profileId, 42);
    assert.equal(ctx.organizationId, 777);
    assert.equal(ctx.orgName, 'ТОО Ромашка');
    assert.equal(ctx.phoneNumber, '7011234567');
    assert.deepEqual(ctx.decryptedSecret, Buffer.from(session.secret, 'base64'));
  });

  it('should expose a working signer bound to the envelope key', () => {
    const ctx = unsealCredentials(sealCredentials({ device, session }));
    const sig = ctx.signer.sign('payload');

    const v = crypto.createVerify('SHA256');
    v.update('payload');
    v.end();
    assert.ok(v.verify(crypto.createPublicKey(ctx.device.privateKey), Buffer.from(sig, 'base64')));
  });

  it('should give different merchants different signing keys', () => {
    const a = unsealCredentials(sealCredentials({ device: createDeviceIdentity(), session }));
    const b = unsealCredentials(sealCredentials({ device: createDeviceIdentity(), session }));
    assert.notEqual(a.device.deviceId, b.device.deviceId);
    assert.notEqual(a.signer.sign('same'), b.signer.sign('same'));
  });

  it('should merge an app override over the defaults', () => {
    const ctx = unsealCredentials(sealCredentials({ device, session, app: { model: 'iPhone14,2' } }));
    assert.equal(ctx.app.model, 'iPhone14,2');
    assert.ok(ctx.app.version, 'other APP fields should still be present');
  });

  it('should reject a tampered envelope', () => {
    const sealed = sealCredentials({ device, session });
    const buf = Buffer.from(sealed, 'base64');
    buf[40] ^= 0xff;
    assert.throws(() => unsealCredentials(buf.toString('base64')), { code: 'invalid_credentials' });
  });

  it('should reject empty or non-string input', () => {
    assert.throws(() => unsealCredentials(''), { code: 'invalid_credentials' });
    assert.throws(() => unsealCredentials(undefined), { code: 'invalid_credentials' });
    assert.throws(() => unsealCredentials('not-base64-at-all!!'), { code: 'invalid_credentials' });
  });

  it('should refuse an onboarding envelope where credentials are expected', () => {
    const onboarding = sealOnboarding({ processId: 'p1', device });
    assert.throws(() => unsealCredentials(onboarding), { code: 'wrong_envelope_type' });
  });

  it('should refuse a credentials envelope where onboarding is expected', () => {
    const creds = sealCredentials({ device, session });
    assert.throws(() => unsealOnboarding(creds), { code: 'wrong_envelope_type' });
  });

  it('should refuse a raw legacy vtokenSecret blob', () => {
    // Тот же ключ и тот же формат, что у конверта — спасает только проверка typ.
    const legacy = encryptSecret(crypto.randomBytes(32));
    assert.throws(() => unsealCredentials(legacy), { code: 'invalid_credentials' });
  });

  it('should refuse an unknown envelope version', () => {
    const future = encryptSecret(
      Buffer.from(JSON.stringify({ v: 99, typ: 'kaspi.credentials', device, session })),
    );
    assert.throws(() => unsealCredentials(future), { code: 'unsupported_version' });
  });

  it('should refuse an envelope whose device key is unusable', () => {
    const broken = encryptSecret(
      Buffer.from(
        JSON.stringify({
          v: 1,
          typ: 'kaspi.credentials',
          device: { ...device, privateKey: 'bm90LWEta2V5' },
          session,
        }),
      ),
    );
    assert.throws(() => unsealCredentials(broken), { code: 'invalid_credentials' });
  });

  it('should not reseal when the envelope already uses the primary key', () => {
    const ctx = unsealCredentials(sealCredentials({ device, session }));
    assert.equal(ctx.resealed, null);
  });
});

describe('onboarding envelope', () => {
  it('should round-trip the in-flight login state', () => {
    const state = unsealOnboarding(
      sealOnboarding({ processId: 'proc-1', userToken: 'ut-1', device, phoneNumber: '7011234567' }),
    );
    assert.equal(state.processId, 'proc-1');
    assert.equal(state.userToken, 'ut-1');
    assert.equal(state.phoneNumber, '7011234567');
    assert.equal(state.device.deviceId, device.deviceId);
    assert.ok(state.signer.sign('x'));
  });

  it('should carry the device forward so re-sealing keeps the same identity', () => {
    const first = unsealOnboarding(sealOnboarding({ processId: 'p', device }));
    const second = unsealOnboarding(sealOnboarding({ processId: 'p', device: first.storedDevice }));
    assert.equal(second.device.deviceId, device.deviceId);
    assert.equal(second.device.pk, first.device.pk);
  });

  it('should expire after the TTL', () => {
    const stale = sealOnboarding({
      processId: 'p',
      device,
      iat: new Date(Date.now() - ONBOARDING_TTL_MS - 1000).toISOString(),
    });
    assert.throws(() => unsealOnboarding(stale), { code: 'onboarding_expired' });
  });

  it('should accept a blob issued just now', () => {
    const fresh = sealOnboarding({ processId: 'p', device, iat: new Date().toISOString() });
    assert.equal(unsealOnboarding(fresh).processId, 'p');
  });
});

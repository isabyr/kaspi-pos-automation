import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { createDeviceIdentity } = await import('../src/device.js');
const { sealCredentials, sealOnboarding } = await import('../src/envelope.js');
const { requireCredentials, REFRESH_HEADER } = await import('../src/middleware/credentials.js');

const fakeRes = () => {
  const res = { statusCode: null, body: null, headers: {} };
  res.status = (c) => {
    res.statusCode = c;
    return res;
  };
  res.json = (b) => {
    res.body = b;
    return res;
  };
  res.set = (k, v) => {
    res.headers[k] = v;
    return res;
  };
  return res;
};

const run = (headers) => {
  const req = { headers };
  const res = fakeRes();
  let nextCalls = 0;
  requireCredentials(req, res, () => nextCalls++);
  return { req, res, nextCalls };
};

const device = createDeviceIdentity();
const activeSession = {
  tokenSN: 'TSN-1',
  secret: crypto.randomBytes(32).toString('base64'),
  profileId: 3,
  orgName: 'Org',
  phoneNumber: '7010000000',
};

describe('requireCredentials', () => {
  it('should 401 with missing_credentials when the header is absent', () => {
    const { res, nextCalls } = run({});
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'missing_credentials');
    assert.equal(nextCalls, 0);
  });

  it('should 401 with invalid_credentials on garbage', () => {
    const { res, nextCalls } = run({ 'x-kaspi-credentials': 'not-an-envelope' });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'invalid_credentials');
    assert.equal(nextCalls, 0);
  });

  it('should 401 with wrong_envelope_type for an onboarding blob', () => {
    const onboarding = sealOnboarding({ processId: 'p', device });
    const { res, nextCalls } = run({ 'x-kaspi-credentials': onboarding });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'wrong_envelope_type');
    assert.equal(nextCalls, 0);
  });

  it('should 401 with not_authenticated when the envelope carries no session', () => {
    const sealed = sealCredentials({ device, session: { tokenSN: null, secret: null } });
    const { res, nextCalls } = run({ 'x-kaspi-credentials': sealed });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.code, 'not_authenticated');
    assert.equal(nextCalls, 0);
  });

  it('should attach the merchant context and call next() once', () => {
    const sealed = sealCredentials({ device, session: activeSession });
    const { req, res, nextCalls } = run({ 'x-kaspi-credentials': sealed });

    assert.equal(nextCalls, 1);
    assert.equal(res.statusCode, null);
    assert.equal(req.merchant.device.deviceId, device.deviceId);
    assert.equal(req.merchant.tokenSN, 'TSN-1');
    assert.equal(req.merchant.orgName, 'Org');
    assert.ok(req.merchant.signer.sign('x'));
  });

  it('should alias req.session to the same context object', () => {
    const sealed = sealCredentials({ device, session: activeSession });
    const { req } = run({ 'x-kaspi-credentials': sealed });
    assert.equal(req.session, req.merchant);
  });

  it('should expose the raw envelope for payment tracking', () => {
    const sealed = sealCredentials({ device, session: activeSession });
    const { req } = run({ 'x-kaspi-credentials': sealed });
    assert.equal(req.merchant.rawCredentials, sealed);
  });

  it('should not set the refresh header when the key is current', () => {
    const sealed = sealCredentials({ device, session: activeSession });
    const { res } = run({ 'x-kaspi-credentials': sealed });
    assert.equal(res.headers[REFRESH_HEADER], undefined);
  });

  it('should isolate merchants — each context signs with its own key', () => {
    const a = run({ 'x-kaspi-credentials': sealCredentials({ device, session: activeSession }) });
    const b = run({
      'x-kaspi-credentials': sealCredentials({ device: createDeviceIdentity(), session: activeSession }),
    });

    assert.notEqual(a.req.merchant.device.deviceId, b.req.merchant.device.deviceId);
    assert.notEqual(a.req.merchant.signer.sign('same'), b.req.merchant.signer.sign('same'));
  });
});

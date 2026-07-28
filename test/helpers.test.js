import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Set TOKEN_SECRET_KEY before importing (helpers imports from crypto via config chain)
process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { generateUUID, nowISO, entranceCookie, extractUserToken, signedQrPayHeaders } = await import(
  '../src/helpers.js'
);

const ctx = (over = {}) => ({
  device: { deviceId: 'DEV-1', installId: 'INST-1', pk: 'PK-1', pkTag: 'TAG-1', pinHash: 'PIN-1' },
  app: {
    locale: 'ru-RU',
    build: '1107',
    platform: 'iOS',
    platformVer: '18.4',
    version: '4.112.1',
  },
  signer: { signRequest: () => 'STUB-SIGN' },
  tokenSN: 'TSN-1',
  decryptedSecret: Buffer.from('0123456789abcdef0123456789abcdef', 'hex'),
  profileId: 42,
  ...over,
});

describe('generateUUID', () => {
  it('should return an uppercase UUID', () => {
    const uuid = generateUUID();
    assert.match(uuid, /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/);
  });

  it('should return unique values', () => {
    const a = generateUUID();
    const b = generateUUID();
    assert.notEqual(a, b);
  });
});

describe('nowISO', () => {
  it('should return ISO-like string with timezone offset', () => {
    const result = nowISO();
    // Should match pattern like 2025-05-09T12:00:00.000+0600
    assert.match(result, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{4}$/);
  });
});

describe('entranceCookie', () => {
  it('should emit exactly the device values from the context', () => {
    const cookie = entranceCookie(ctx());
    assert.ok(cookie.includes('deviceId=DEV-1;'));
    assert.ok(cookie.includes('installId=INST-1;'));
    assert.ok(cookie.includes('pk=PK-1;'));
    assert.ok(cookie.includes('pkTag=TAG-1;'));
    assert.ok(cookie.includes('is_mobile_app=true'));
  });

  it('should emit app values from the context', () => {
    const cookie = entranceCookie(ctx());
    assert.ok(cookie.includes('locale=ru-RU;'));
    assert.ok(cookie.includes('ma_bld=1107;'));
    assert.ok(cookie.includes('ma_ver=4.112.1;'));
  });

  it('should use per-merchant values, not a global device', () => {
    const a = entranceCookie(ctx({ device: { deviceId: 'A', installId: 'A', pk: 'A', pkTag: 'A' } }));
    const b = entranceCookie(ctx({ device: { deviceId: 'B', installId: 'B', pk: 'B', pkTag: 'B' } }));
    assert.notEqual(a, b);
  });

  it('should include user_token when provided', () => {
    const cookie = entranceCookie(ctx(), 'my-token');
    assert.ok(cookie.includes('user_token=my-token'));
  });

  it('should not include user_token when not provided', () => {
    const cookie = entranceCookie(ctx());
    assert.ok(!cookie.includes('user_token='));
  });
});

describe('signedQrPayHeaders', () => {
  const url = 'https://qrpay.kaspi.kz/v01/qr-token/create';

  it('should take device headers from the context', () => {
    const h = signedQrPayHeaders(url, ctx());
    assert.equal(h['X-Install-ID'], 'INST-1');
    assert.equal(h['X-Device-ID'], 'DEV-1');
    assert.equal(h['X-Kb-TokenSn'], 'TSN-1');
    assert.equal(h['X-PI'], '42');
  });

  it('should render a null profileId as an empty string', () => {
    const h = signedQrPayHeaders(url, ctx({ profileId: null }));
    assert.equal(h['X-PI'], '');
  });

  it('should sign via the context signer with the X-SH list', () => {
    const calls = [];
    const h = signedQrPayHeaders(
      url,
      ctx({
        signer: {
          signRequest: (u, headers, xsh, body) => {
            calls.push({ u, xsh, body });
            return 'SIG';
          },
        },
      }),
      '{"a":1}',
    );
    assert.equal(h['X-Sign'], 'SIG');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].u, url);
    assert.equal(calls[0].xsh, h['X-SH']);
    assert.equal(calls[0].body, '{"a":1}');
  });

  it('should compute a 6-digit TokenSnMac', () => {
    const h = signedQrPayHeaders(url, ctx());
    assert.match(h['X-Kb-TokenSnMac'], /^\d{6}$/);
  });
});

describe('extractUserToken', () => {
  it('should extract user_token from set-cookie headers', () => {
    const fakeResp = {
      headers: {
        raw: () => ({
          'set-cookie': ['user_token=abc123; Path=/; HttpOnly'],
        }),
      },
    };
    assert.equal(extractUserToken(fakeResp), 'abc123');
  });

  it('should return null when no user_token cookie', () => {
    const fakeResp = {
      headers: {
        raw: () => ({
          'set-cookie': ['other=value; Path=/'],
        }),
      },
    };
    assert.equal(extractUserToken(fakeResp), null);
  });

  it('should return null when no set-cookie header', () => {
    const fakeResp = {
      headers: {
        raw: () => ({}),
      },
    };
    assert.equal(extractUserToken(fakeResp), null);
  });
});

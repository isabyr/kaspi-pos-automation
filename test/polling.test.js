import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { resolveEvent, buildPayload, sameRetry, resolveTimeout, SCANNED_MAX_AGE_MS } =
  await import('../src/polling.js');

describe('resolveEvent — qr', () => {
  it('should return null for intermediate statuses', () => {
    assert.equal(resolveEvent('qr', 'QrTokenCreated'), null);
    assert.equal(resolveEvent('qr', 'Wait'), null);
  });

  it('should map terminal statuses', () => {
    assert.equal(resolveEvent('qr', 'Processed'), 'payment.success');
    assert.equal(resolveEvent('qr', 'CancelledByUser'), 'payment.failed');
    assert.equal(resolveEvent('qr', 'InsufficientFunds'), 'payment.failed');
    assert.equal(resolveEvent('qr', 'IrisDestBlockCode10'), 'payment.failed');
    assert.equal(resolveEvent('qr', 'Expired'), 'payment.expired');
    assert.equal(resolveEvent('qr', 'QrTokenDiscarded'), 'payment.expired');
  });

  it('should treat an unknown status as failure rather than hanging forever', () => {
    assert.equal(resolveEvent('qr', 'SomethingKaspiAddedLater'), 'payment.failed');
  });
});

describe('resolveEvent — invoice', () => {
  it('should return null while the invoice is outstanding', () => {
    assert.equal(resolveEvent('invoice', 'RemotePaymentCreated'), null);
  });

  it('should map terminal statuses', () => {
    assert.equal(resolveEvent('invoice', 'Processed'), 'payment.success');
    assert.equal(resolveEvent('invoice', 'RemotePaymentCanceled'), 'payment.failed');
    assert.equal(resolveEvent('invoice', 'RemotePaymentRejected'), 'payment.failed');
    assert.equal(resolveEvent('invoice', 'Expired'), 'payment.expired');
  });

  it('should not treat the qr intermediate status as intermediate here', () => {
    assert.equal(resolveEvent('invoice', 'QrTokenCreated'), 'payment.failed');
  });
});

describe('resolveTimeout', () => {
  const NOW = 1_800_000_000_000;
  const iso = (ms) => new Date(ms).toISOString();
  const qr = (over = {}) => ({
    type: 'qr',
    status: 'QrTokenCreated',
    createdAt: NOW,
    meta: { expireDate: iso(NOW + 5 * 60_000) },
    ...over,
  });

  it('should keep polling while the QR is still within its ExpireDate', () => {
    assert.equal(resolveTimeout(qr(), NOW + 60_000), null);
  });

  it('should expire an unscanned QR once its ExpireDate passes', () => {
    const out = resolveTimeout(qr(), NOW + 6 * 60_000);
    assert.equal(out.event, 'payment.expired');
  });

  it('should keep polling a scanned QR long past its ExpireDate', () => {
    // Клиент отсканировал и держит экран оплаты. Снять его с опроса здесь —
    // значит потерять payment.success по «случайной» поздней оплате.
    const entry = qr({ status: 'Wait', scannedAt: NOW });
    assert.equal(resolveTimeout(entry, NOW + 6 * 60_000), null);
  });

  it('should give up on a scanned QR after SCANNED_MAX_AGE_MS, as lost', () => {
    const entry = qr({ status: 'Wait', scannedAt: NOW });
    const out = resolveTimeout(entry, NOW + SCANNED_MAX_AGE_MS + 1);
    // Именно lost, а не expired: заплатил клиент или нет — мы не знаем.
    assert.equal(out.event, 'payment.lost');
    assert.equal(out.data.Code, 'polling_failed');
  });

  it('should not strand a payment Kaspi gave no ExpireDate for', () => {
    const entry = qr({ meta: {} });
    assert.equal(resolveTimeout(entry, NOW + 60_000), null);
    assert.equal(
      resolveTimeout(entry, NOW + SCANNED_MAX_AGE_MS + 1).event,
      'payment.lost',
    );
  });

  it('should leave an already-terminal status to the normal poll path', () => {
    const entry = qr({ status: 'Processed' });
    assert.equal(resolveTimeout(entry, NOW + 6 * 60_000), null);
  });
});

describe('buildPayload', () => {
  const entry = {
    paymentId: '12345',
    type: 'qr',
    status: 'QrTokenCreated',
    meta: {
      merchantRef: 'shop-01',
      orderId: 'ORDER-9',
      orgName: 'ТОО Ромашка',
      phoneNumber: '7010000000',
      amount: 5000,
      qrToken: 'https://qr.kaspi.kz/abc',
      receiptUrl: 'https://receipt',
      orderNumber: 'KZ-1',
    },
  };

  it('should carry the client-supplied merchant reference', () => {
    const p = buildPayload('payment.success', entry, { Status: 'Processed' });
    assert.equal(p.merchantRef, 'shop-01');
    assert.equal(p.orderId, 'ORDER-9');
    assert.equal(p.orgName, 'ТОО Ромашка');
    assert.equal(p.phoneNumber, '7010000000');
  });

  it('should prefer meta.amount over the Kaspi payload', () => {
    const p = buildPayload('payment.success', entry, { Status: 'Processed', Amount: 999 });
    assert.equal(p.amount, 5000);
  });

  it('should prefer the fresh Kaspi status over the stale tracked one', () => {
    const p = buildPayload('payment.success', entry, { Status: 'Processed' });
    assert.equal(p.status, 'Processed');
  });

  it('should fall back to the tracked status when Kaspi sends none', () => {
    const p = buildPayload('payment.lost', entry, {});
    assert.equal(p.status, 'QrTokenCreated');
  });

  it('should emit an ISO timestamp', () => {
    const p = buildPayload('payment.success', entry, { Status: 'Processed' });
    assert.ok(!Number.isNaN(new Date(p.timestamp).getTime()));
  });

  it('should tolerate an entry with no meta', () => {
    const p = buildPayload('payment.lost', { paymentId: '1', type: 'qr', status: 'Wait' }, {});
    assert.equal(p.merchantRef, null);
    assert.equal(p.amount, null);
    assert.equal(p.paymentId, '1');
  });

  it('should never leak the credential envelope', () => {
    const p = buildPayload('payment.success', { ...entry, credentials: 'SEALED-BLOB' }, { Status: 'Processed' });
    assert.ok(!JSON.stringify(p).includes('SEALED-BLOB'));
  });
});

describe('sameRetry', () => {
  const hook = { url: 'https://hooks.example/kaspi' };
  const payload = { paymentId: '1', event: 'payment.success', merchantRef: 'shop-01' };
  const retry = (over = {}) => ({ hook, payload: { ...payload, ...over } });

  it('should match an identical retry', () => {
    assert.equal(sameRetry(retry(), hook, payload), true);
  });

  it('should not collide across merchants sharing one webhook URL', () => {
    assert.equal(sameRetry(retry({ merchantRef: 'shop-02' }), hook, payload), false);
  });

  it('should distinguish payments and events', () => {
    assert.equal(sameRetry(retry({ paymentId: '2' }), hook, payload), false);
    assert.equal(sameRetry(retry({ event: 'payment.failed' }), hook, payload), false);
  });

  it('should distinguish webhook urls', () => {
    assert.equal(sameRetry(retry(), { url: 'https://other' }, payload), false);
  });

  it('should treat missing and null merchantRef as the same', () => {
    const noRef = { paymentId: '1', event: 'payment.success' };
    assert.equal(sameRetry({ hook, payload: noRef }, hook, { ...noRef, merchantRef: null }), true);
  });
});

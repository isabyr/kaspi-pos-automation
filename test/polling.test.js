import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { resolveEvent, buildPayload, sameRetry } = await import('../src/polling.js');

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

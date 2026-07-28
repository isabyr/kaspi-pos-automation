import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import { KASPI_QRPAY_URL } from './config.js';
import { signedQrPayHeaders } from './helpers.js';
import { unsealCredentials } from './envelope.js';
import { getWebhooksByEvent } from './webhookStore.js';
import { logger } from './logger.js';
import { runPool } from './util/pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TRACKED_FILE = path.join(__dirname, '..', 'tracked-payments.json');

// ─── Tracked payments ───

const trackedPayments = new Map();

// ─── Persistence ───

const saveTracked = () => {
  try {
    const data = Object.fromEntries(trackedPayments);
    fs.writeFileSync(TRACKED_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    logger.error('POLLING', 'Failed to save tracked payments', err.message);
  }
};

const loadTracked = () => {
  try {
    if (!fs.existsSync(TRACKED_FILE)) return;
    const raw = fs.readFileSync(TRACKED_FILE, 'utf8');
    const data = JSON.parse(raw);
    let legacy = 0;
    for (const [id, entry] of Object.entries(data)) {
      // Записи версии 1.x хранили сессию в sessionHeaders и опрашивались общим
      // ключом устройства. Ключа мерчанта у них нет — опросить их больше нечем.
      if (!entry.credentials) {
        legacy++;
        logger.warn(
          'POLLING',
          `Dropping pre-2.0 tracked payment ${id} (no credential envelope) — status unknown, sending payment.lost`,
        );
        sendWebhooks(
          'payment.lost',
          buildPayload('payment.lost', entry, {
            Status: 'CredentialsMissing',
            StatusDesc: 'Платёж создан до перехода на credential envelope, статус неизвестен',
          }),
        );
        continue;
      }
      trackedPayments.set(id, entry);
    }
    if (trackedPayments.size > 0) {
      logger.info('POLLING', `Restored ${trackedPayments.size} tracked payments from file`);
    }
    if (legacy > 0) {
      logger.warn('POLLING', `Discarded ${legacy} pre-2.0 tracked payment(s)`);
      saveTracked();
    }
  } catch (err) {
    logger.error('POLLING', 'Failed to load tracked payments', err.message);
  }
};

// ─── Pending retries (persisted) ───

const RETRY_FILE = path.join(__dirname, '..', 'webhook-retries.json');
let pendingRetries = [];

const saveRetries = () => {
  try {
    fs.writeFileSync(RETRY_FILE, JSON.stringify(pendingRetries, null, 2));
  } catch (err) {
    logger.error('WEBHOOK', 'Failed to save retries', err.message);
  }
};

const loadRetries = () => {
  try {
    if (!fs.existsSync(RETRY_FILE)) return;
    const raw = fs.readFileSync(RETRY_FILE, 'utf8');
    pendingRetries = JSON.parse(raw);
    if (pendingRetries.length > 0) {
      logger.info('WEBHOOK', `Restored ${pendingRetries.length} pending retries from file`);
    }
  } catch (err) {
    logger.error('WEBHOOK', 'Failed to load retries', err.message);
    pendingRetries = [];
  }
};

// ─── Status → event mapping ───

const QR_FINAL_STATUSES = {
  Processed: 'payment.success',
  CancelledByUser: 'payment.failed',
  NotConfirmedByUser: 'payment.failed',
  CancelledByExternalSource: 'payment.failed',
  ProcessingFailed: 'payment.failed',
  Rejected: 'payment.failed',
  InsufficientFunds: 'payment.failed',
  InsufficientFundsError: 'payment.failed',
  Error: 'payment.failed',
  IrisSrcBlockCode1: 'payment.failed',
  IrisSrcBlockCode3: 'payment.failed',
  IrisSrcBlockCode9: 'payment.failed',
  IrisDestBlockCode3: 'payment.failed',
  IrisDestBlockCode5: 'payment.failed',
  IrisDestBlockCode7: 'payment.failed',
  IrisDestBlockCode10: 'payment.failed',
  QrTokenDiscarded: 'payment.expired',
  Expired: 'payment.expired',
};

const INVOICE_FINAL_STATUSES = {
  Processed: 'payment.success',
  RemotePaymentCanceled: 'payment.failed',
  RemotePaymentRejected: 'payment.failed',
  Expired: 'payment.expired',
};

const QR_INTERMEDIATE = new Set(['QrTokenCreated', 'Wait']);
const INVOICE_INTERMEDIATE = new Set(['RemotePaymentCreated']);

// ─── Track a payment ───

export const trackPayment = (paymentId, type, credentials, meta = {}) => {
  trackedPayments.set(String(paymentId), {
    paymentId: String(paymentId),
    type,
    status: type === 'qr' ? 'QrTokenCreated' : 'RemotePaymentCreated',
    credentials,
    meta,
    createdAt: Date.now(),
    retryCount: 0,
  });
  saveTracked();
  logger.info('POLLING', `Tracking ${type} payment ${paymentId}`, meta.merchantRef ? { merchantRef: meta.merchantRef } : undefined);
};

// ─── Fetch status from Kaspi (quiet — no loggedFetch) ───

const fetchStatus = async (entry) => {
  const { paymentId, type } = entry;

  // Каждый платёж опрашивается ключом своего мерчанта, а не общим.
  let session;
  try {
    session = unsealCredentials(entry.credentials);
  } catch (err) {
    logger.error('POLLING', `Cannot unseal credentials for payment ${paymentId}: ${err.code || err.message}`);
    return { error: 'session_expired' };
  }

  if (!session.tokenSN || !session.decryptedSecret) {
    return { error: 'session_expired' };
  }

  let url;
  if (type === 'qr') {
    url = `${KASPI_QRPAY_URL}/v02/kaspi-qr/status?qrOperationId=${paymentId}`;
  } else {
    url = `${KASPI_QRPAY_URL}/v02/remote/details?operationId=${paymentId}`;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const resp = await fetch(url, {
      headers: signedQrPayHeaders(url, session),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const json = await resp.json();
    return json;
  } catch (err) {
    logger.error('POLLING', `Error fetching status for ${paymentId}:`, err.message);
    return null;
  }
};

// ─── Send webhooks ───

const fetchWithTimeout = async (url, options, timeoutMs = 10000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return resp;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
};

/**
 * Все мерчанты шлют вебхуки на один URL, поэтому (url, paymentId, event) больше
 * не различает записи — без merchantRef повторы разных мерчантов гасят друг друга.
 */
export const sameRetry = (r, hook, payload) =>
  r.hook.url === hook.url &&
  r.payload.paymentId === payload.paymentId &&
  r.payload.event === payload.event &&
  (r.payload.merchantRef || null) === (payload.merchantRef || null);

const sendWebhook = async (hook, payload, attempt = 1) => {
  const body = JSON.stringify(payload);
  const signature =
    'sha256=' +
    crypto
      .createHmac('sha256', hook.secret || '')
      .update(body)
      .digest('hex');

  try {
    const resp = await fetchWithTimeout(hook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Signature': signature,
      },
      body,
    });
    logger.info('WEBHOOK', `→ ${hook.url} | ${resp.status} ${resp.statusText}`);
    // Remove from pending retries on success
    pendingRetries = pendingRetries.filter((r) => !sameRetry(r, hook, payload));
    saveRetries();
  } catch (err) {
    logger.error('WEBHOOK', `→ ${hook.url} | attempt ${attempt} FAILED: ${err.message}`);
    if (attempt < 3) {
      // Save retry to disk so it survives restarts
      pendingRetries.push({
        hook,
        payload,
        attempt: attempt + 1,
        executeAfter: Date.now() + (attempt === 1 ? 5000 : 30000),
      });
      saveRetries();
    } else {
      logger.error('WEBHOOK', `→ ${hook.url} | FAILED after 3 retries`);
      // Remove from pending retries
      pendingRetries = pendingRetries.filter((r) => !sameRetry(r, hook, payload));
      saveRetries();
    }
  }
};

const sendWebhooks = (event, payload) => {
  const hooks = getWebhooksByEvent(event);
  for (const hook of hooks) {
    sendWebhook(hook, payload);
  }
};

// ─── Process pending retries ───

const processRetries = async () => {
  const now = Date.now();
  const due = pendingRetries.filter((r) => r.executeAfter <= now);
  // Remove due items from list before executing (they'll be re-added on failure)
  pendingRetries = pendingRetries.filter((r) => r.executeAfter > now);
  saveRetries();

  for (const r of due) {
    await sendWebhook(r.hook, r.payload, r.attempt);
  }
};

// ─── Resolve event from status ───

export const resolveEvent = (type, status) => {
  if (type === 'qr') {
    if (QR_INTERMEDIATE.has(status)) return null;
    return QR_FINAL_STATUSES[status] || 'payment.failed';
  } else {
    if (INVOICE_INTERMEDIATE.has(status)) return null;
    return INVOICE_FINAL_STATUSES[status] || 'payment.failed';
  }
};

// ─── Poll cycle ───

/** Опрашивает один платёж. Возвращает true, если карта изменилась. */
const pollEntry = async (id, entry) => {
  // TTL check via expireDate
  if (entry.meta?.expireDate) {
    const expiry = new Date(entry.meta.expireDate).getTime();
    if (Date.now() > expiry && resolveEvent(entry.type, entry.status) === null) {
      logger.info('POLLING', `Payment ${id} expired (TTL)`);
      sendWebhooks(
        'payment.expired',
        buildPayload('payment.expired', entry, { Status: 'Expired', StatusDesc: 'Время оплаты истекло' }),
      );
      trackedPayments.delete(id);
      return true;
    }
  }

  const result = await fetchStatus(entry);

  // Handle session expiration
  if (result && result.error === 'session_expired') {
    entry.retryCount++;
    if (entry.retryCount > 3) {
      logger.warn('POLLING', `Payment ${id} — session expired, sending session.expired webhook`);
      sendWebhooks(
        'payment.failed',
        buildPayload('payment.failed', entry, {
          Status: 'SessionExpired',
          StatusDesc: 'Сессия Kaspi истекла, невозможно проверить статус платежа',
          Code: 'session_expired',
        }),
      );
      trackedPayments.delete(id);
      return true;
    }
    return false;
  }

  if (!result || !result.Data) {
    // Kaspi returns StatusCode -101001 when session was evicted (login from another device)
    if (result && result.StatusCode === -101001) {
      logger.warn('POLLING', `Payment ${id} — session evicted (StatusCode -101001)`);
      sendWebhooks(
        'payment.lost',
        buildPayload('payment.lost', entry, {
          Status: 'SessionExpired',
          StatusDesc: 'Сессия Kaspi вытеснена (вход с другого устройства), статус платежа неизвестен',
          // Клиенту нужно заново пройти onboarding именно для этого мерчанта.
          Code: 'session_evicted',
        }),
      );
      trackedPayments.delete(id);
      return true;
    }

    entry.retryCount++;
    if (entry.retryCount > 10) {
      logger.warn('POLLING', `Removing payment ${id} after 10 failed attempts`);
      sendWebhooks(
        'payment.lost',
        buildPayload('payment.lost', entry, {
          Status: 'PollingFailed',
          StatusDesc: `Не удалось получить статус платежа после ${entry.retryCount} попыток`,
          Code: 'polling_failed',
        }),
      );
      trackedPayments.delete(id);
      return true;
    }
    return false;
  }

  // Reset retry count on successful fetch
  entry.retryCount = 0;

  const newStatus = result.Data.Status;
  if (newStatus === entry.status) return false;

  logger.info('POLLING', `Payment ${id}: ${entry.status} → ${newStatus}`);
  entry.status = newStatus;

  const event = resolveEvent(entry.type, newStatus);
  if (event) {
    sendWebhooks(event, buildPayload(event, entry, result.Data));
    trackedPayments.delete(id);
  }
  return true;
};

/**
 * Платежи одного мерчанта опрашиваются последовательно (не долбим одну сессию
 * Kaspi), разные мерчанты — параллельно, иначе один зависший запрос с таймаутом
 * 15 с останавливает очередь для всех остальных.
 */
const pollOnce = async () => {
  const groups = new Map();
  for (const [id, entry] of trackedPayments) {
    const key = entry.credentials || 'unknown';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push([id, entry]);
  }

  let changed = false;
  await runPool([...groups.values()], POLL_CONCURRENCY, async (entries) => {
    for (const [id, entry] of entries) {
      if (await pollEntry(id, entry)) changed = true;
    }
  });

  if (changed) {
    saveTracked();
  }
};

export const buildPayload = (event, entry, data) => ({
  event,
  merchantRef: entry.meta?.merchantRef || null,
  orderId: entry.meta?.orderId || null,
  orgName: entry.meta?.orgName || null,
  phoneNumber: entry.meta?.phoneNumber || null,
  paymentId: entry.paymentId,
  type: entry.type,
  status: data.Status || entry.status,
  statusDesc: data.StatusDesc || '',
  amount: entry.meta?.amount || data.Amount || null,
  qrToken: entry.meta?.qrToken || null,
  receiptUrl: entry.meta?.receiptUrl || data.ReceiptUrl || null,
  orderNumber: entry.meta?.orderNumber || data.OrderNumber || null,
  data,
  timestamp: new Date().toISOString(),
});

// ─── Polling loop (setTimeout-based, no overlap) ───

let pollActive = false;
let pollTimer = null;
const POLL_MS = 3000;
const POLL_CONCURRENCY = Number(process.env.POLL_CONCURRENCY) || 5;

const scheduleNext = () => {
  if (!pollActive) return;
  pollTimer = setTimeout(async () => {
    try {
      if (trackedPayments.size > 0) {
        await pollOnce();
      }
      // Process pending webhook retries
      if (pendingRetries.length > 0) {
        await processRetries();
      }
    } catch (err) {
      logger.error('POLLING', 'Unexpected error:', err.message);
    }
    scheduleNext();
  }, POLL_MS);
};

export const startPolling = () => {
  if (pollActive) return;

  // Load persisted state
  loadTracked();
  loadRetries();

  pollActive = true;
  scheduleNext();
  logger.info('POLLING', 'Started (interval: 3s, persistence: enabled)');
};

export const stopPolling = () => {
  pollActive = false;
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  saveTracked();
  saveRetries();
  logger.info('POLLING', 'Stopped');
};

export const getTrackedPayments = () => Object.fromEntries(trackedPayments);

/** Снимает с опроса все платежи, поставленные с этим конвертом (logout). */
export const dropPaymentsFor = (credentials) => {
  let dropped = 0;
  for (const [id, entry] of trackedPayments) {
    if (entry.credentials === credentials) {
      trackedPayments.delete(id);
      dropped++;
    }
  }
  if (dropped > 0) {
    saveTracked();
    logger.info('POLLING', `Dropped ${dropped} tracked payment(s) on logout`);
  }
  return dropped;
};

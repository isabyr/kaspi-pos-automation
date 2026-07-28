import { encryptSecret, decryptSecretWithKeyIndex } from './crypto.js';
import { buildDevice } from './device.js';
import { createSigner } from './signer.js';
import { APP } from './config.js';

// ─── Credential envelope ───
//
// Сервер не хранит данные мерчантов. Всё, что нужно для работы от его имени —
// устройство, приватный ключ и сессия Kaspi — упаковано в один зашифрованный
// «конверт» (AES-256-GCM под TOKEN_SECRET_KEYS) и отдаётся клиенту.
// Клиент присылает его обратно в заголовке X-Kaspi-Credentials на каждый запрос.
// Для клиента конверт непрозрачен: прочитать приватный ключ он не может.

export const ENVELOPE_VERSION = 1;

export const TYPE_CREDENTIALS = 'kaspi.credentials';
export const TYPE_ONBOARDING = 'kaspi.onboarding';

// Незавершённый вход живёт ровно столько, сколько занимает ввод SMS-кода.
export const ONBOARDING_TTL_MS = 15 * 60 * 1000;

export class EnvelopeError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

const seal = (payload) => encryptSecret(Buffer.from(JSON.stringify(payload), 'utf8'));

/**
 * Расшифровывает и валидирует конверт.
 * Возвращает {payload, staleKey} — staleKey означает, что конверт зашифрован
 * устаревшим ключом и его следует перевыпустить.
 */
const open = (b64, expectedType) => {
  if (typeof b64 !== 'string' || b64.length === 0) {
    throw new EnvelopeError('Envelope is missing or empty', 'invalid_credentials');
  }

  let plaintext;
  let keyIndex;
  try {
    ({ plaintext, keyIndex } = decryptSecretWithKeyIndex(b64));
  } catch {
    throw new EnvelopeError('Envelope could not be decrypted', 'invalid_credentials');
  }

  let payload;
  try {
    payload = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new EnvelopeError('Envelope is not valid JSON', 'invalid_credentials');
  }

  // Проверка типа обязательна: без неё onboarding-конверт (или устаревший
  // vtokenSecret — тот же ключ, тот же формат) можно подсунуть вместо credentials.
  if (payload?.typ !== expectedType) {
    throw new EnvelopeError(
      `Expected a ${expectedType} envelope, got ${payload?.typ || 'unknown'}`,
      'wrong_envelope_type',
    );
  }

  if (payload.v !== ENVELOPE_VERSION) {
    throw new EnvelopeError(
      `Unsupported envelope version ${payload.v}. Re-onboard this merchant.`,
      'unsupported_version',
    );
  }

  return { payload, staleKey: keyIndex > 0 };
};

// ─── Credentials ───

export const sealCredentials = ({ device, session, app }) =>
  seal({
    v: ENVELOPE_VERSION,
    typ: TYPE_CREDENTIALS,
    device: {
      deviceId: device.deviceId,
      installId: device.installId,
      pinHash: device.pinHash,
      privateKey: device.privateKey,
    },
    session: {
      tokenSN: session.tokenSN,
      secret: session.secret,
      profileId: session.profileId ?? null,
      organizationId: session.organizationId ?? null,
      orgName: session.orgName ?? null,
      phoneNumber: session.phoneNumber ?? null,
    },
    app: app || {},
    iat: new Date().toISOString(),
  });

/**
 * Разворачивает конверт в контекст мерчанта: device + app + signer + сессия.
 * Именно этот объект получают entranceCookie() и signedQrPayHeaders().
 */
export const unsealCredentials = (b64) => {
  const { payload, staleKey } = open(b64, TYPE_CREDENTIALS);

  let device;
  try {
    device = buildDevice(payload.device);
  } catch {
    throw new EnvelopeError('Envelope contains an unusable device key', 'invalid_credentials');
  }

  const s = payload.session || {};

  return {
    device,
    app: { ...APP, ...(payload.app || {}) },
    signer: createSigner(device.privateKey),
    tokenSN: s.tokenSN,
    decryptedSecret: s.secret ? Buffer.from(s.secret, 'base64') : null,
    profileId: s.profileId,
    organizationId: s.organizationId,
    orgName: s.orgName,
    phoneNumber: s.phoneNumber,
    issuedAt: payload.iat,
    // Конверт зашифрован старым ключом — вернём клиенту свежий.
    resealed: staleKey ? sealCredentials({ device: payload.device, session: s, app: payload.app }) : null,
  };
};

// ─── Onboarding ───

export const sealOnboarding = ({ processId, userToken, device, phoneNumber, iat }) =>
  seal({
    v: ENVELOPE_VERSION,
    typ: TYPE_ONBOARDING,
    processId,
    userToken: userToken || null,
    device,
    phoneNumber: phoneNumber || null,
    iat: iat || new Date().toISOString(),
  });

export const unsealOnboarding = (b64) => {
  const { payload } = open(b64, TYPE_ONBOARDING);

  const age = Date.now() - new Date(payload.iat).getTime();
  if (!Number.isFinite(age) || age > ONBOARDING_TTL_MS) {
    throw new EnvelopeError('Onboarding session has expired. Start over.', 'onboarding_expired');
  }

  let device;
  try {
    device = buildDevice(payload.device);
  } catch {
    throw new EnvelopeError('Onboarding envelope contains an unusable device key', 'invalid_credentials');
  }

  return {
    processId: payload.processId,
    userToken: payload.userToken,
    phoneNumber: payload.phoneNumber,
    iat: payload.iat,
    storedDevice: payload.device, // сериализуемая форма — для повторной упаковки
    device,
    app: { ...APP },
    signer: createSigner(device.privateKey),
  };
};

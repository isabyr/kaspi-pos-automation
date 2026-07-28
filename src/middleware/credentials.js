import { unsealCredentials } from '../envelope.js';

export const CREDENTIALS_HEADER = 'x-kaspi-credentials';
export const REFRESH_HEADER = 'X-Kaspi-Credentials-Refresh';

/**
 * Разворачивает конверт мерчанта из заголовка X-Kaspi-Credentials.
 * Возвращает контекст или бросает EnvelopeError с полем code.
 */
export const contextFromRequest = (req, res) => {
  const raw = req.headers[CREDENTIALS_HEADER];
  if (!raw) {
    const err = new Error('Missing X-Kaspi-Credentials header.');
    err.code = 'missing_credentials';
    throw err;
  }

  const ctx = unsealCredentials(raw);

  // Конверт зашифрован устаревшим ключом — отдаём клиенту свежий и дальше
  // работаем уже с ним (в том числе при постановке платежа на опрос).
  if (ctx.resealed && res) res.set(REFRESH_HEADER, ctx.resealed);
  ctx.rawCredentials = ctx.resealed || raw;

  return ctx;
};

export const requireCredentials = (req, res, next) => {
  let ctx;
  try {
    ctx = contextFromRequest(req, res);
  } catch (err) {
    return res.status(401).json({
      error: err.message,
      code: err.code || 'invalid_credentials',
    });
  }

  if (!ctx.tokenSN || !ctx.decryptedSecret) {
    return res.status(401).json({
      error: 'Credentials do not contain an active Kaspi session. Re-onboard this merchant.',
      code: 'not_authenticated',
    });
  }

  req.merchant = ctx;
  req.session = ctx; // алиас, чтобы тела обработчиков не менялись
  next();
};

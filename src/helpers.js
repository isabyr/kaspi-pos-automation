import crypto from 'crypto';
import fetch from 'node-fetch';
import { UA_NATIVE } from './config.js';
import { computeTokenSnMac } from './crypto.js';

// ─── Utilities ───

export const generateUUID = () => crypto.randomUUID().toUpperCase();

export const nowISO = () => {
  const d = new Date();
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0');
  const mm = String(Math.abs(off) % 60).padStart(2, '0');
  return (
    d
      .toISOString()
      .replace('Z', '')
      .replace(/\.\d{3}/, `.${String(d.getMilliseconds()).padStart(3, '0')}`) +
    sign +
    hh +
    mm
  );
};

// ─── Cookie builder ───

export const entranceCookie = (ctx, extraUserToken) => {
  const { device: d, app: a } = ctx;
  let c = `deviceId=${d.deviceId}; installId=${d.installId}; is_mobile_app=true; locale=${a.locale}; ma_bld=${a.build}; ma_platform_type=${a.platform}; ma_platform_ver=${a.platformVer}; ma_ver=${a.version}; pk=${d.pk}; pkTag=${d.pkTag}; xs=R:0|E:0|RH:0|N:0`;
  if (extraUserToken) c += `; user_token=${extraUserToken}`;
  return c;
};

// ─── Extract user_token from set-cookie ───

export const extractUserToken = (resp) => {
  const raw = resp.headers.raw()['set-cookie'] || [];
  for (const c of raw) {
    const m = c.match(/user_token=([^;]+)/);
    if (m) return m[1];
  }
  return null;
};

// ─── Logged fetch wrapper ───

// Заголовки, по которым можно выдать себя за мерчанта. С несколькими мерчантами
// это означало бы N сессий в открытом виде в логах.
const REDACTED_HEADERS = new Set(['cookie', 'x-kb-tokensn', 'x-kb-tokensnmac', 'x-kaspi-credentials', 'x-sign']);

export const redactHeaders = (headers = {}) =>
  Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k, REDACTED_HEADERS.has(k.toLowerCase()) ? '[REDACTED]' : v]),
  );

// Полный дамп запросов включается только явно: LOG_HTTP=1
const LOG_HTTP = process.env.LOG_HTTP === '1' || process.env.LOG_HTTP === 'true';

export const loggedFetch = async (url, options = {}) => {
  const method = (options.method || 'GET').toUpperCase();
  console.log(`\n>>> ${method} ${url}`);
  if (LOG_HTTP) {
    if (options.headers) console.log('>>> Headers:', JSON.stringify(redactHeaders(options.headers), null, 2));
    if (options.body) {
      try {
        console.log('>>> Body:', JSON.parse(options.body));
      } catch {
        console.log('>>> Body:', options.body);
      }
    }
  }

  const resp = await fetch(url, options);
  console.log(`<<< ${resp.status} ${resp.statusText}`);

  // Тело ответа тоже секретное: /kpentrance/finish возвращает tokenSN и x509.
  if (LOG_HTTP) {
    const cloned = resp.clone();
    let body;
    try {
      body = await cloned.json();
    } catch {
      try {
        body = await cloned.text();
      } catch {
        body = '[unreadable]';
      }
    }
    console.log('<<< Response:', typeof body === 'object' ? JSON.stringify(body, null, 2) : body);
  }
  return resp;
};

// ─── Signed QR-pay headers (merchant context passed as parameter) ───

export const signedQrPayHeaders = (url, ctx, body) => {
  const { device: d, app: a, signer } = ctx;
  const xsh =
    'url,X-Install-ID,X-PI,X-App-Bld,X-Platform-Ver,X-Locale,X-App-Ver,X-Device-ID,X-SV,X-Time,X-Platform-Type,X-Call,X-Kb-TokenSnMac,X-Kb-TokenSn';
  const headers = {
    'X-Kb-TokenSn': ctx.tokenSN,
    'X-Kb-TokenSnMac': computeTokenSnMac(ctx.tokenSN, ctx.decryptedSecret),
    'X-PI': ctx.profileId != null ? String(ctx.profileId) : '',
    'X-Install-ID': d.installId,
    'X-Device-ID': d.deviceId,
    'X-App-Ver': a.version,
    'X-App-Bld': a.build,
    'X-Platform-Type': a.platform,
    'X-Platform-Ver': a.platformVer,
    'X-Locale': a.locale,
    'X-Time': nowISO(),
    'X-Request-ID': generateUUID(),
    'X-Call': 'notConnected',
    'X-SV': '2',
    'X-SH': xsh,
    'User-Agent': UA_NATIVE,
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  headers['X-Sign'] = signer.signRequest(url, headers, xsh, body);
  return headers;
};

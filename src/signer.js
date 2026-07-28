import { ecSign, signDataPayload, computeXSign } from './crypto.js';

/**
 * Связывает приватный ключ мерчанта с функциями подписи, чтобы остальной код
 * не таскал ключ через каждый вызов.
 */
export const createSigner = (privateKey) => ({
  sign: (data) => ecSign(data, privateKey),
  signData: (dataB64) => signDataPayload(dataB64, privateKey),
  signRequest: (url, headers, xsh, body) => computeXSign(url, headers, xsh, body, privateKey),
});

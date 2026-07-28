import crypto from 'crypto';

// ─── Device identity ───
//
// Каждый мерчант имеет собственный device fingerprint и собственную пару ключей
// ECDSA P-256. Kaspi привязывает сессию к устройству, поэтому повторный вход с
// новым устройством вытесняет предыдущую сессию (StatusCode -101001).

/**
 * Создаёт новое устройство: идентификаторы + свежая пара ключей ECDSA P-256.
 * Возвращает сериализуемый объект — именно он попадает в credential envelope.
 */
export const createDeviceIdentity = () => {
  const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    deviceId: crypto.randomUUID().toUpperCase(),
    installId: crypto.randomUUID().toUpperCase(),
    pinHash: crypto.createHash('md5').update(crypto.randomBytes(16)).digest('hex'),
    privateKey: keyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
};

export const importPrivateKey = (privateKeyB64) =>
  crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });

/**
 * Выводит публичный материал из приватного ключа: несжатую точку EC (pk),
 * её md5 (pkTag) и SPKI DER (x509). Хранить их в envelope не нужно.
 */
export const derivePublicMaterial = (privateKey) => {
  const der = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const x509 = der.toString('base64');
  const pk = der.subarray(der.length - 65).toString('base64');
  const pkTag = crypto.createHash('md5').update(pk).digest('hex');
  return { pk, pkTag, x509 };
};

/**
 * Разворачивает сохранённое устройство в полный объект для подписи запросов.
 */
export const buildDevice = ({ deviceId, installId, pinHash, privateKey }) => {
  const key = importPrivateKey(privateKey);
  return { deviceId, installId, pinHash, privateKey: key, ...derivePublicMaterial(key) };
};

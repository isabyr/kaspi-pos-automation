import { Router } from 'express';
import { APP, UA_NATIVE, ENTRANCE_HEADERS_BASE, KASPI_ENTRANCE_URL, KASPI_MTOKEN_URL } from '../config.js';
import { createEmptySession, applyOrgContext } from '../session.js';
import {
  generateEcdhKeyPair,
  ecdhPublicKeyB64,
  deriveSharedSecret,
  computeTokenSnMac,
  computeXSU,
} from '../crypto.js';
import { createDeviceIdentity } from '../device.js';
import { buildDevice } from '../device.js';
import { createSigner } from '../signer.js';
import { sealCredentials, sealOnboarding, unsealOnboarding } from '../envelope.js';
import { contextFromRequest } from '../middleware/credentials.js';
import { loggedFetch, extractUserToken, entranceCookie, generateUUID, nowISO } from '../helpers.js';
import { dropPaymentsFor } from '../polling.js';

const router = Router();

// ─── Onboarding state ───
//
// Сервер не хранит незавершённые входы. Всё состояние трёхшагового входа
// (processId, user_token, только что созданное устройство) едет к клиенту в
// зашифрованном onboardingState и возвращается на следующем шаге.

const onboardingContext = (state) => ({
  device: state.device,
  app: state.app,
  signer: state.signer,
});

const readOnboarding = (req, res) => {
  const raw = req.body?.onboardingState;
  if (!raw) {
    res.status(400).json({ error: 'onboardingState required (from /api/auth/init)', code: 'missing_onboarding_state' });
    return null;
  }
  try {
    return unsealOnboarding(raw);
  } catch (err) {
    res.status(400).json({ error: err.message, code: err.code || 'invalid_onboarding_state' });
    return null;
  }
};

// ═══════════════════════════════════════════════════
//  Step 1 — Init entrance (get processId)
// ═══════════════════════════════════════════════════

router.post('/init', async (req, res) => {
  // Повторный вход должен использовать УЖЕ существующее устройство мерчанта:
  // регистрация нового устройства на тот же номер вытесняет живую сессию Kaspi.
  let storedDevice;
  if (req.headers['x-kaspi-credentials']) {
    try {
      const existing = contextFromRequest(req, res);
      storedDevice = {
        deviceId: existing.device.deviceId,
        installId: existing.device.installId,
        pinHash: existing.device.pinHash,
        privateKey: existing.device.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      };
    } catch (err) {
      return res.status(401).json({ error: err.message, code: err.code || 'invalid_credentials' });
    }
  } else {
    storedDevice = createDeviceIdentity();
  }

  const device = buildDevice(storedDevice);
  const ctx = { device, app: { ...APP }, signer: createSigner(device.privateKey) };
  const session = createEmptySession();

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/entrance/?auth=2&appBuild=${APP.build}&appVersion=${APP.version}&platformVersion=${APP.platformVer}&platformType=IOS&deviceBrand=${APP.brand}&deviceModel=${APP.model}&deviceId=${device.deviceId}&installId=${device.installId}&frontCameraAvailable=true&sf=registration&pc=KPEntrance&noPass=0`,
        Cookie: entranceCookie(ctx),
      },
      body: JSON.stringify({
        data: {},
        Data: {
          auth: '2',
          appBuild: APP.build,
          appVersion: APP.version,
          platformVersion: APP.platformVer,
          platformType: 'IOS',
          deviceBrand: APP.brand,
          deviceModel: APP.model,
          deviceId: device.deviceId,
          installId: device.installId,
          frontCameraAvailable: 'true',
          sf: 'registration',
          pc: 'KPEntrance',
          noPass: '0',
        },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    if (ut) session.userToken = ut;

    const body = await resp.json();
    if (body.meta?.pId) session.processId = body.meta.pId;

    res.json({
      success: !!session.processId,
      processId: session.processId,
      reusedDevice: !!req.headers['x-kaspi-credentials'],
      onboardingState: session.processId
        ? sealOnboarding({
            processId: session.processId,
            userToken: session.userToken,
            device: storedDevice,
          })
        : null,
      view: body.view?.code,
      body,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Step 2 — Send phone number (triggers SMS)
// ═══════════════════════════════════════════════════

router.post('/send-phone', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return res.status(400).json({ error: 'phoneNumber required (e.g. 7XXXXXXXXX)' });

  const state = readOnboarding(req, res);
  if (!state) return;

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/universal-enter-phone-number?pId=${state.processId}&firstPage=KPUniversalEnterPhoneNumber`,
        Cookie: entranceCookie(onboardingContext(state), state.userToken),
      },
      body: JSON.stringify({
        meta: { pId: state.processId, sn: 'EnterPhoneNumber' },
        data: { phoneNumber },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    const body = await resp.json();
    const smsSent = body.view?.code === 'EnterOtp';

    res.json({
      success: smsSent,
      processId: state.processId,
      // user_token ротируется на каждом ответе — клиент обязан хранить свежий.
      onboardingState: sealOnboarding({
        processId: state.processId,
        userToken: ut || state.userToken,
        device: state.storedDevice,
        phoneNumber,
        iat: state.iat,
      }),
      desc: body.data?.desc,
      view: body.view?.code,
      body,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Step 3 — Submit SMS OTP code
// ═══════════════════════════════════════════════════

router.post('/verify-otp', async (req, res) => {
  const { otp } = req.body;
  if (!otp) return res.status(400).json({ error: 'otp required' });

  const state = readOnboarding(req, res);
  if (!state) return;

  try {
    const resp = await loggedFetch(`${KASPI_ENTRANCE_URL}/api/v1/entrance/step`, {
      method: 'POST',
      headers: {
        ...ENTRANCE_HEADERS_BASE,
        Referer: `${KASPI_ENTRANCE_URL}/process/universal-enter-phone-number?pId=${state.processId}&firstPage=KPUniversalEnterPhoneNumber`,
        Cookie: entranceCookie(onboardingContext(state), state.userToken),
      },
      body: JSON.stringify({
        meta: { pId: state.processId, sn: 'ViewEnterOtp' },
        data: { userOtp: otp, inputType: 'auto' },
        actType: 'Success',
      }),
    });

    const ut = extractUserToken(resp);
    const body = await resp.json();

    if (body.data?.type === 'kpDeviceRegistration' || body.view?.code === 'KPMobileCall') {
      // OTP verified — automatically call finish
      const finishResult = await doFinish(state);
      res.json({
        success: true,
        processId: state.processId,
        step: 'finished',
        message: 'OTP verified and finish completed',
        otpBody: body,
        ...finishResult,
      });
    } else {
      res.json({
        success: false,
        processId: state.processId,
        step: 'otp_response',
        onboardingState: sealOnboarding({
          processId: state.processId,
          userToken: ut || state.userToken,
          device: state.storedDevice,
          phoneNumber: state.phoneNumber,
          iat: state.iat,
        }),
        body,
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════
//  Finish logic — produces the credential envelope
// ═══════════════════════════════════════════════════

async function doFinish(state) {
  const { device, signer } = state;
  const app = state.app;
  const session = createEmptySession();
  session.processId = state.processId;
  session.phoneNumber = state.phoneNumber;

  // Эфемерная пара ECDH живёт только внутри этого вызова.
  const ecdhKeyPair = generateEcdhKeyPair();
  const ecdhX509 = ecdhPublicKeyB64(ecdhKeyPair);

  const signedDataObj = {
    installId: device.installId,
    time: nowISO(),
    auth: [{ value: '', type: 'pincode' }],
    userIdHash: '',
  };
  const signedDataB64 = Buffer.from(JSON.stringify(signedDataObj)).toString('base64');

  const finishUrl = `${KASPI_ENTRANCE_URL}/api/v1/kpentrance/finish`;
  const finishHeaders = {
    'Content-Type': 'application/json',
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
    'User-Agent': UA_NATIVE,
    'X-Time': nowISO(),
    'X-Call': 'notConnected',
    'X-Platform-Type': app.platform,
    'X-PkTag': device.pkTag,
    'X-SU': computeXSU(finishUrl),
    'X-Net-Type': 'WIFI/ETHERNET',
    'X-Emulator': '0',
    'X-Locale': app.locale,
    'X-SV': '2',
    'X-Request-ID': generateUUID(),
    'X-Time-Zone': 'GMT+05:00',
    'X-SH': 'url,X-Time-Zone,X-Request-ID,X-Net-Type,X-Emulator,X-Call,X-Platform-Type,X-Locale,X-Time,X-SV',
  };
  const finishBody = JSON.stringify({
    signed: { sign: signer.signData(signedDataB64), data: signedDataB64 },
    guard: { pinHash: device.pinHash, x509: ecdhX509 },
    processId: state.processId,
  });
  finishHeaders['X-Sign'] = signer.signRequest(finishUrl, finishHeaders, finishHeaders['X-SH'], finishBody);

  const resp = await loggedFetch(finishUrl, {
    method: 'POST',
    headers: finishHeaders,
    body: finishBody,
  });

  const body = await resp.json();

  if (!body.success || !body.data?.tokenSN) {
    throw new Error('Finish failed: ' + JSON.stringify(body));
  }

  session.tokenSN = body.data.tokenSN;

  let rawSecret = null;
  if (body.data.x509) {
    try {
      rawSecret = deriveSharedSecret(ecdhKeyPair.privateKey, body.data.x509);
      console.log('vtoken activated successfully');
    } catch (e) {
      console.error('ECDH key agreement failed:', e.message);
    }
  }

  // Fetch org context
  const orgUrl = `${KASPI_MTOKEN_URL}/v08/organizations/org-context-otp`;
  const orgHeaders = {
    'Content-Type': 'application/json',
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
    'User-Agent': UA_NATIVE,
    'X-Kb-TokenSn': session.tokenSN,
    'X-Kb-TokenSnMac': computeTokenSnMac(session.tokenSN, rawSecret),
    'X-Install-ID': device.installId,
    'X-App-Ver': app.version,
    'X-App-Bld': app.build,
    'X-Locale': app.locale,
    'X-Call': 'notConnected',
    'X-Time': nowISO(),
    'X-S': 'R:0|E:0|RH:0|N:0',
    'X-SV': '2',
    'X-Kb-Client-Ip': '192.168.1.96',
    'X-PkTag': device.pkTag,
    'X-SU': computeXSU(orgUrl),
    'X-SH':
      'url,X-Kb-Client-Ip,X-Time,X-App-Ver,X-SV,X-Locale,X-App-Bld,X-Install-ID,X-Kb-TokenSn,X-S,X-Kb-TokenSnMac,X-Call',
    'X-Request-ID': generateUUID(),
  };
  const orgPayload = JSON.stringify({
    DeviceInformation: {
      SdkVersion: 'AOTP service',
      DeviceId: device.deviceId,
      ApplicationId: 'kz.kaspi.business',
      ScreenWidth: app.screenW,
      Model: app.model,
      ScreenHeight: app.screenH,
      DeviceName: app.deviceName,
      VersionName: app.version,
      BuildRelease: `${app.platform} ${app.platformVer}`,
      Brand: app.brand,
      Board: app.platformVer,
      Platform: app.platform,
      Product: 'Kaspi Pay',
      frontCameraAvailable: true,
      VersionCode: app.build,
      InstallId: device.installId,
    },
    OrganizationId: 0,
  });
  orgHeaders['X-Sign'] = signer.signRequest(orgUrl, orgHeaders, orgHeaders['X-SH'], orgPayload);

  const orgResp = await loggedFetch(orgUrl, {
    method: 'POST',
    headers: orgHeaders,
    body: orgPayload,
  });

  const orgBody = await orgResp.json();

  if (orgBody.Data?.Current?.ProfileId) {
    applyOrgContext(session, orgBody.Data);
  }

  // tokenSN и общий секрет больше никогда не покидают сервер в открытом виде —
  // они уезжают клиенту только внутри зашифрованного конверта.
  const credentials = sealCredentials({
    device: state.storedDevice,
    session: {
      tokenSN: session.tokenSN,
      secret: rawSecret ? rawSecret.toString('base64') : null,
      profileId: session.profileId,
      organizationId: session.organizationId,
      orgName: session.orgName,
      phoneNumber: session.phoneNumber,
    },
  });

  return {
    credentials,
    authenticated: true,
    deviceId: device.deviceId,
    profileId: session.profileId,
    organizationId: session.organizationId,
    orgName: session.orgName,
    phone: session.phoneNumber,
    organizations: orgBody.Data?.Organizations,
  };
}

// ─── Envelope status (does not touch Kaspi — see GET /api/session/check for that) ───

router.get('/session', (req, res) => {
  let ctx;
  try {
    ctx = contextFromRequest(req, res);
  } catch (err) {
    return res.status(401).json({ authenticated: false, error: err.message, code: err.code || 'invalid_credentials' });
  }

  res.json({
    authenticated: !!(ctx.tokenSN && ctx.decryptedSecret),
    deviceId: ctx.device.deviceId,
    profileId: ctx.profileId,
    organizationId: ctx.organizationId,
    orgName: ctx.orgName,
    phone: ctx.phoneNumber,
    issuedAt: ctx.issuedAt,
  });
});

router.post('/session', (req, res) =>
  res.status(410).json({
    error: 'POST /api/auth/session was removed in 2.0.0. Use GET /api/auth/session with X-Kaspi-Credentials.',
    code: 'gone',
  }),
);

// ─── Logout ───
//
// Хранить нечего — клиент просто выбрасывает конверт. Сервер лишь снимает с
// опроса платежи этого мерчанта, чтобы они не висели до исчерпания попыток.

router.post('/logout', (req, res) => {
  let dropped = 0;
  if (req.headers['x-kaspi-credentials']) {
    dropped = dropPaymentsFor(req.headers['x-kaspi-credentials']);
  }
  res.json({ success: true, dropped });
});

export default router;

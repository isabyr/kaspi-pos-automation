import { Router } from 'express';
import { KASPI_QRPAY_URL } from '../config.js';
import { loggedFetch, signedQrPayHeaders } from '../helpers.js';
import { contextFromRequest } from '../middleware/credentials.js';

const router = Router();

// ─── Check session validity ───

router.get('/check', async (req, res) => {
  // 1. Unseal the credential envelope — report the reason rather than a bare 401
  let session;
  try {
    session = contextFromRequest(req, res);
  } catch (err) {
    return res.status(401).json({
      active: false,
      error: err.message,
      code: err.code || 'invalid_credentials',
    });
  }

  // 2. The envelope may be valid but carry no Kaspi session yet
  if (!session.tokenSN || !session.decryptedSecret) {
    return res.status(401).json({
      active: false,
      error: 'Credentials do not contain an active Kaspi session. Re-onboard this merchant.',
      code: 'not_authenticated',
    });
  }

  // 3. Ping Kaspi API to verify the token is still accepted
  try {
    const url = `${KASPI_QRPAY_URL}/v02/history/operations`;
    const payload = JSON.stringify({
      EndDate: new Date().toISOString().slice(0, 10),
      LastTransactionDate: '',
      StatementPeriodCode: 0,
    });
    const headers = { ...signedQrPayHeaders(url, session, payload), 'Content-Type': 'application/json' };
    const resp = await loggedFetch(url, {
      method: 'POST',
      headers,
      body: payload,
    });

    const body = await resp.json().catch(() => ({}));

    // Kaspi may return HTTP 200 but with error StatusCode in body
    if (resp.ok && (!body.StatusCode || body.StatusCode === 0)) {
      return res.json({ active: true });
    }

    return res.status(resp.ok ? 401 : resp.status).json({
      active: false,
      error: body.Message || body.message || 'Session rejected by Kaspi API.',
      code: body.StatusCode || body.Code,
      details: body,
    });
  } catch (err) {
    return res.status(500).json({ active: false, error: err.message });
  }
});

export default router;

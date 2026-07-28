# Project Guidelines

## Build & Configuration

- **Node.js ≥ 20.6** required (ES modules via `"type": "module"`).
- Create `.env` with `TOKEN_SECRET_KEY` (64-char hex, 32 bytes) before first run — see `.env.example`.
  It encrypts every credential envelope; losing it forces every merchant to re-onboard.
  Rotate via `TOKEN_SECRET_KEYS=<new>,<old>` — old envelopes keep working and are re-issued
  through the `X-Kaspi-Credentials-Refresh` response header.
- No files are generated at startup. Devices and keypairs are minted per merchant during
  onboarding and live only inside the client-held envelope.
- Migrating a 1.x install: `npm run mint-credentials` (see `scripts/mint-credentials.js`).

## Architecture

- **Entry point**: `server.js` — Express, routes under `/api/*`, static `public/`.
- **Fully stateless per merchant.** The server stores no merchant records. Everything needed to
  act as a merchant — device id, install id, pin hash, ECDSA P-256 private key and the Kaspi
  session — is sealed into one AES-256-GCM envelope (`src/envelope.js`) and returned to the
  caller, which replays it in `X-Kaspi-Credentials` on every request.
- **Onboarding is stateless too**: the 3-step SMS flow carries its own `onboardingState`
  envelope; nothing is held between requests.
- **Source**: `src/envelope.js` (seal/unseal), `src/device.js` (mint + derive pk/pkTag/x509),
  `src/signer.js` (binds a private key to the signing functions), `src/crypto.js` (primitives,
  no module state), `src/helpers.js`, `src/session.js`, `src/middleware/credentials.js`.
- **Routes**: `src/routes/{auth,invoice,qr,history,refund,session}.js`. All except `auth`
  mount `requireCredentials`, which puts the merchant context on `req.merchant`.
- **The only server-side state** is `tracked-payments.json` (in-flight payments, each carrying
  its own sealed envelope), `webhook-retries.json`, `webhooks.json` and `logs/`.
- **Webhooks** are global (one URL for all merchants); payloads carry the client-supplied
  `merchantRef`/`orderId` so the receiving backend can attribute them.

## Invariants worth protecting

- `computeXSign`'s canonical string is pinned by `test/crypto.test.js`. Changing it by one byte
  makes Kaspi reject every request with an opaque error.
- Each merchant must keep its own device fingerprint. Registering a new device against a phone
  that already has one evicts the live session (`StatusCode -101001`), which is why
  `POST /api/auth/init` reuses the device from an existing envelope when one is supplied.
- Never log or return `tokenSN`, the vtoken secret, or a private key in the clear.
  `loggedFetch` redacts secret headers and only dumps bodies under `LOG_HTTP=1`.

## Code Style

- **ES Modules** (`import`/`export`), semicolons, `const`, arrow functions.
- `async/await` with try/catch, JSON `{ error }` on failure; add a machine-readable `code`
  when the client needs to distinguish "re-onboard" from "retry".
- ESLint configured (`eslint.config.js`). Tests are `node --test test/`.

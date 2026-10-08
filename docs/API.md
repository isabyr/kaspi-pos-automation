# 📖 API Documentation

Kaspi POS Automation предоставляет REST API для работы с платежами Kaspi Pay: авторизация по SMS, выставление счетов, QR-оплата, история операций и возвраты.

**Base URL:** `http://localhost:3000`

---

## Содержание

- [Аутентификация](#аутентификация)
  - [Заголовки сессии](#заголовки-сессии)
- [Health Check](#health-check)
- [Auth — Авторизация](#auth--авторизация)
  - [POST /api/auth/init](#post-apiauthinit)
  - [POST /api/auth/send-phone](#post-apiauthsend-phone)
  - [POST /api/auth/verify-otp](#post-apiauthverify-otp)
  - [GET /api/auth/session](#get-apiauthsession)
  - [POST /api/auth/logout](#post-apiauthlogout)
- [Invoice — Счета](#invoice--счета)
  - [GET /api/invoice/client-info](#get-apiinvoiceclient-info)
  - [POST /api/invoice/create](#post-apiinvoicecreate)
  - [GET /api/invoice/details](#get-apiinvoicedetails)
  - [POST /api/invoice/cancel](#post-apiinvoicecancel)
  - [POST /api/invoice/history](#post-apiinvoicehistory)
- [QR — QR-оплата](#qr--qr-оплата)
  - [POST /api/qr/create](#post-apiqrcreate)
  - [GET /api/qr/status](#get-apiqrstatus)
- [History — История операций](#history--история-операций)
  - [POST /api/history/operations](#post-apihistoryoperations)
  - [POST /api/history/details](#post-apihistorydetails)
- [Refund — Возвраты](#refund--возвраты)
  - [POST /api/refund/create](#post-apirefundcreate)
- [Session — Проверка сессии](#session--проверка-сессии)
  - [GET /api/session/check](#get-apisessioncheck)
- [Webhooks — Уведомления](#webhooks--уведомления)
  - [Настройка](#настройка)
  - [События](#события)
  - [Формат payload](#формат-payload)
  - [Подпись (HMAC)](#подпись-hmac)
  - [Повторные попытки (Retry)](#повторные-попытки-retry)

---

## Аутентификация

Сервер **не хранит данные мерчантов**. После 3-шаговой SMS-авторизации клиент получает один зашифрованный **credential envelope** — «конверт», в котором лежит всё необходимое для работы от имени мерчанта: устройство (deviceId, installId, pinHash), приватный ключ ECDSA P-256 и сессия Kaspi. Клиент хранит конверт у себя и присылает его на каждый запрос.

Благодаря этому один сервер обслуживает **любое число мерчантов**: у каждого своё устройство и свой ключ подписи, поэтому вход одного не вытесняет сессию другого.

Конверт непрозрачен: он зашифрован серверным `TOKEN_SECRET_KEY` (AES-256-GCM), прочитать приватный ключ клиент не может — только сохранить и вернуть обратно.

### Заголовки сессии

Все эндпоинты кроме `/api/auth/init`, `/api/auth/send-phone`, `/api/auth/verify-otp` и `/health` требуют заголовок:

| Заголовок | Тип | Обязательный | Описание |
|---|---|---|---|
| `X-Kaspi-Credentials` | `string` | ✅ | Credential envelope, полученный в `/api/auth/verify-otp` |

> 🔐 Конверт — это **bearer-секрет**: кто им владеет, тот действует от имени мерчанта. Храните его как пароль и передавайте только по TLS.

### Ответ при ошибке авторизации

```json
{
  "error": "Envelope could not be decrypted",
  "code": "invalid_credentials"
}
```

| `code` | Что делать |
|---|---|
| `missing_credentials` | Заголовок не передан |
| `invalid_credentials` | Конверт повреждён или зашифрован неизвестным ключом → onboarding заново |
| `wrong_envelope_type` | Прислан `onboardingState` вместо конверта |
| `unsupported_version` | Формат конверта устарел → onboarding заново |
| `not_authenticated` | Конверт валиден, но не содержит сессии Kaspi → onboarding заново |

### Ротация ключа шифрования

Если сервер запущен с `TOKEN_SECRET_KEYS=<новый>,<старый>`, конверты под старым ключом продолжают работать, а в ответе приходит заголовок:

```
X-Kaspi-Credentials-Refresh: <перевыпущенный конверт>
```

Клиенту достаточно сохранить его вместо прежнего — простоя не будет.

---

## Health Check

### `GET /health`

Проверка работоспособности сервера.

**Ответ:**

```json
{ "status": "ok" }
```

---

## Auth — Авторизация

Трёхшаговый процесс авторизации через SMS-код Kaspi.

> ⚠️ **Важно:** Для входа используйте номер телефона аккаунта **кассира** Kaspi Pay.

### `POST /api/auth/init`

Начинает авторизацию. Создаёт **новое устройство** (deviceId, installId, pinHash + пара ключей ECDSA) и возвращает `onboardingState` — зашифрованный слепок незавершённого входа. Сервер ничего не запоминает: `onboardingState` нужно передать в следующие два шага.

**Заголовки:**

| Заголовок | Обязательный | Описание |
|---|---|---|
| `X-Kaspi-Credentials` | ❌ | При **повторном входе** передайте текущий конверт мерчанта — тогда будет переиспользовано его устройство |

> ⚠️ **Важно при повторном входе.** Kaspi привязывает сессию к устройству: регистрация нового устройства на тот же номер **вытесняет**活 сессию (`StatusCode -101001`). Всегда передавайте существующий конверт, если мерчант уже был авторизован.

**Тело запроса:** не требуется

**Пример запроса:**

```bash
# первичный onboarding
curl -X POST http://localhost:3000/api/auth/init

# повторный вход — переиспользуем устройство
curl -X POST http://localhost:3000/api/auth/init \
  -H "X-Kaspi-Credentials: <конверт>"
```

**Успешный ответ:**

```json
{
  "success": true,
  "processId": "abc123-...",
  "reusedDevice": false,
  "onboardingState": "BASE64...",
  "view": "EnterPhoneNumber",
  "body": { ... }
}
```

---

### `POST /api/auth/send-phone`

Отправка номера телефона — инициирует отправку SMS-кода.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `phoneNumber` | `string` | ✅ | Номер телефона (формат: `7XXXXXXXXXX`) |
| `onboardingState` | `string` | ✅ | Значение из `/api/auth/init` |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/auth/send-phone \
  -H "Content-Type: application/json" \
  -d '{"phoneNumber": "77001234567", "onboardingState": "BASE64..."}'
```

**Успешный ответ:**

```json
{
  "success": true,
  "processId": "abc123-...",
  "onboardingState": "BASE64...",
  "desc": "Код отправлен на номер +7 700 *** ** 67",
  "view": "EnterOtp",
  "body": { ... }
}
```

> ⚠️ В ответе приходит **обновлённый** `onboardingState` — Kaspi ротирует `user_token` на каждом шаге. Используйте свежее значение на следующем шаге, иначе вход не завершится.

**Ответ при отказе Kaspi** (`success: false`) дополнительно содержит `errorCode` и `errorMessage` — причину отказа. Например, `errorCode: "OldVersionToUpdate"` означает, что версия приложения ниже минимальной у Kaspi и вход не работает **у всех** кассиров: обновите `APP_VERSION` / `APP_BUILD` в `.env` и перезапустите сервер.

---

### `POST /api/auth/verify-otp`

Подтверждение SMS-кода. При успехе автоматически завершает авторизацию и возвращает данные сессии.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `otp` | `string` | ✅ | SMS-код |
| `onboardingState` | `string` | ✅ | Значение из `/api/auth/send-phone` |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"otp": "1234", "onboardingState": "BASE64..."}'
```

**Успешный ответ:**

```json
{
  "success": true,
  "processId": "abc123-...",
  "step": "finished",
  "message": "OTP verified and finish completed",
  "credentials": "BASE64...",
  "authenticated": true,
  "deviceId": "9F3A...-...",
  "profileId": 12345,
  "organizationId": 67890,
  "orgName": "ИП Иванов",
  "phone": "77001234567",
  "organizations": [ ... ]
}
```

> 🔐 **Сохраните `credentials`** рядом с записью мерчанта в своей базе — это единственная копия. Сервер её не хранит. `tokenSN` и секрет vtoken больше не возвращаются в открытом виде.

---

### `GET /api/auth/session`

Показывает содержимое конверта. **Не обращается к Kaspi** — проверяет только сам конверт; чтобы убедиться, что сессия ещё жива на стороне Kaspi, используйте [`GET /api/session/check`](#get-apisessioncheck).

**Пример запроса:**

```bash
curl http://localhost:3000/api/auth/session \
  -H "X-Kaspi-Credentials: <конверт>"
```

**Ответ:**

```json
{
  "authenticated": true,
  "deviceId": "9F3A...-...",
  "profileId": 12345,
  "organizationId": 67890,
  "orgName": "ИП Иванов",
  "phone": "77001234567",
  "issuedAt": "2026-07-28T10:00:00.000Z"
}
```

> `POST /api/auth/session` удалён в 2.0.0 и отвечает `410 Gone`.

---

### `POST /api/auth/logout`

Хранить на сервере нечего — достаточно удалить конверт у себя. Эндпоинт лишь снимает с опроса незавершённые платежи этого мерчанта, чтобы они не висели до исчерпания попыток.

**Заголовки:** `X-Kaspi-Credentials` (необязательно)

**Ответ:**

```json
{ "success": true, "dropped": 2 }
```

---

## Invoice — Счета

Выставление счетов на оплату по номеру телефона клиента.

> 🔒 Все эндпоинты требуют [заголовки сессии](#заголовки-сессии).

### `GET /api/invoice/client-info`

Получение информации о клиенте по номеру телефона.

**Query-параметры:**

| Параметр | Тип | Обязательный | Описание |
|---|---|---|---|
| `phoneNumber` | `string` | ✅ | Номер телефона клиента |

**Пример запроса:**

```bash
curl "http://localhost:3000/api/invoice/client-info?phoneNumber=77001234567" \
  -H "X-Kaspi-Credentials: <конверт>"
```

---

### `POST /api/invoice/create`

Создание счёта на оплату.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `phoneNumber` | `string` | ✅ | Номер телефона клиента |
| `amount` | `number` | ✅ | Сумма в тенге |
| `comment` | `string` | ❌ | Комментарий к платежу |
| `merchantRef` | `string` | ❌ | Ваш идентификатор мерчанта — возвращается в вебхуке без изменений |
| `orderId` | `string` | ❌ | Ваш идентификатор заказа — возвращается в вебхуке без изменений |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/invoice/create \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"phoneNumber": "77001234567", "amount": 1000, "comment": "Оплата заказа #42"}'
```

**Успешный ответ:**

```json
{
  "StatusCode": 0,
  "Data": {
    "Id": 123456,
    "Status": "RemotePaymentCreated",
    "Amount": 1000,
    "ClientMobile": "77001234567",
    "ReceiptUrl": "https://...",
    "OrderNumber": "..."
  }
}
```

---

### `GET /api/invoice/details`

Получение деталей счёта.

**Query-параметры:**

| Параметр | Тип | Обязательный | Описание |
|---|---|---|---|
| `operationId` | `string` | ✅ | ID операции |

**Пример запроса:**

```bash
curl "http://localhost:3000/api/invoice/details?operationId=123456" \
  -H "X-Kaspi-Credentials: <конверт>"
```

---

### `POST /api/invoice/cancel`

Отмена выставленного счёта.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `operationId` | `string` | ✅ | ID операции для отмены |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/invoice/cancel \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"operationId": "123456"}'
```

---

### `POST /api/invoice/history`

Получение истории выставленных счетов (последние 20).

**Тело запроса:** не требуется (пустой JSON `{}`)

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/invoice/history \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{}'
```

---

## QR — QR-оплата

Генерация QR-кодов для оплаты через Kaspi Pay.

> 🔒 Все эндпоинты требуют [заголовки сессии](#заголовки-сессии).

### `POST /api/qr/create`

Создание QR-токена для оплаты.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `amount` | `number` | ✅ | Сумма в тенге |
| `latitude` | `number` | ❌ | Широта (по умолчанию: Алматы) |
| `longitude` | `number` | ❌ | Долгота (по умолчанию: Алматы) |
| `merchantRef` | `string` | ❌ | Ваш идентификатор мерчанта — возвращается в вебхуке без изменений |
| `orderId` | `string` | ❌ | Ваш идентификатор заказа — возвращается в вебхуке без изменений |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/qr/create \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"amount": 500, "merchantRef": "shop-01", "orderId": "ORDER-42"}'
```

**Успешный ответ:**

```json
{
  "StatusCode": 0,
  "Data": {
    "QrOperationId": 789012,
    "QrToken": "https://pay.kaspi.kz/pay/...",
    "ExpireDate": "2025-01-01T12:05:00",
    "Amount": 500,
    "ReceiptUrl": "https://..."
  }
}
```

> 💡 `QrToken` содержит ссылку для оплаты — можно преобразовать в QR-код.

---

### `GET /api/qr/status`

Проверка статуса QR-платежа.

**Query-параметры:**

| Параметр | Тип | Обязательный | Описание |
|---|---|---|---|
| `qrOperationId` | `string` | ✅ | ID QR-операции из `/api/qr/create` |

**Пример запроса:**

```bash
curl "http://localhost:3000/api/qr/status?qrOperationId=789012" \
  -H "X-Kaspi-Credentials: <конверт>"
```

---

## History — История операций

Просмотр истории всех операций (QR + счета).

> 🔒 Все эндпоинты требуют [заголовки сессии](#заголовки-сессии).

### `POST /api/history/operations`

Получение списка операций за период.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `endDate` | `string` | ✅ | Конечная дата (формат: `YYYY-MM-DD`) |
| `lastTransactionDate` | `string` | ❌ | Дата последней транзакции (для пагинации) |
| `statementPeriodCode` | `number` | ❌ | Код периода (по умолчанию: `0`) |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/history/operations \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"endDate": "2025-01-15"}'
```

---

### `POST /api/history/details`

Получение деталей конкретной операции.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `id` | `number` | ✅ | ID операции |
| `operationMethod` | `number` | ❌ | Метод операции (по умолчанию: `0`) |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/history/details \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"id": 123456}'
```

---

## Refund — Возвраты

Возврат средств по ранее проведённой операции.

> 🔒 Все эндпоинты требуют [заголовки сессии](#заголовки-сессии).

### `POST /api/refund/create`

Создание возврата.

**Тело запроса:**

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `qrOperationId` | `number` | ✅ | ID операции для возврата |
| `returnAmount` | `number` | ✅ | Сумма возврата в тенге |

**Пример запроса:**

```bash
curl -X POST http://localhost:3000/api/refund/create \
  -H "Content-Type: application/json" \
  -H "X-Kaspi-Credentials: <конверт>" \
  -d '{"qrOperationId": 789012, "returnAmount": 500}'
```

---

## Session — Проверка сессии

### `GET /api/session/check`

Проверка валидности текущей сессии через запрос к Kaspi API.

> 🔒 Требует [заголовки сессии](#заголовки-сессии).

**Пример запроса:**

```bash
curl "http://localhost:3000/api/session/check" \
  -H "X-Kaspi-Credentials: <конверт>"
```

**Активная сессия:**

```json
{ "active": true }
```

**Неактивная сессия:**

```json
{
  "active": false,
  "error": "Session rejected by Kaspi API.",
  "code": 401,
  "details": { ... }
}
```

---

## Коды ошибок

Все эндпоинты возвращают ошибки в формате:

```json
{ "error": "Описание ошибки" }
```

| HTTP-код | Описание |
|---|---|
| `400` | Отсутствуют обязательные параметры |
| `401` | Отсутствуют или невалидные заголовки сессии |
| `500` | Внутренняя ошибка сервера или ошибка Kaspi API |

---

## Webhooks — Уведомления

Система автоматически отслеживает статусы созданных QR- и invoice-платежей (polling каждые 3 секунды) и отправляет HTTP POST-уведомления (webhooks) на указанные URL при изменении статуса платежа.

### Настройка

Вебхуки **общие для всех мерчантов** — настраиваются в файле `webhooks.json` в корне проекта. Чтобы понять, к какому мерчанту относится уведомление, передавайте `merchantRef` при создании платежа: он возвращается в payload без изменений.

Файл содержит массив объектов:

```json
[
  {
    "url": "https://example.com/webhook",
    "events": ["payment.success", "payment.failed", "payment.expired", "payment.lost"],
    "secret": "your-webhook-secret"
  }
]
```

| Поле | Тип | Обязательный | Описание |
|---|---|---|---|
| `url` | `string` | ✅ | URL, на который будут отправляться уведомления |
| `events` | `string[]` | ✅ | Список событий для подписки |
| `secret` | `string` | ❌ | Секрет для HMAC-подписи (рекомендуется) |

> 💡 Для начала скопируйте `webhooks.example.json` → `webhooks.json` и отредактируйте.

Можно указать несколько вебхуков с разными URL и событиями:

```json
[
  {
    "url": "https://my-crm.com/kaspi-hook",
    "events": ["payment.success"],
    "secret": "crm-secret-key"
  },
  {
    "url": "https://my-accounting.com/hook",
    "events": ["payment.success", "payment.failed", "payment.expired", "payment.lost"],
    "secret": "accounting-secret"
  }
]
```

### События

| Событие | Описание | Когда срабатывает |
|---|---|---|
| `payment.success` | Платёж успешно проведён | QR: статус `Processed`; Invoice: статус `Processed` |
| `payment.failed` | Платёж отклонён / отменён | QR: `CancelledByUser`, `Rejected`, `Error` и др.; Invoice: `RemotePaymentCanceled`, `RemotePaymentRejected` |
| `payment.expired` | Время оплаты истекло | QR: `QrTokenDiscarded`, `Expired`; Invoice: `Expired` |
| `payment.lost` | Статус платежа неизвестен — требуется ручная проверка | Сессия Kaspi вытеснена (`SessionExpired`, `data.Code = "session_evicted"` → мерчанту нужен повторный onboarding) или исчерпаны попытки опроса (`PollingFailed`) |

### Формат payload

При срабатывании события на каждый подписанный URL отправляется POST-запрос с JSON-телом:

```json
{
  "event": "payment.success",
  "merchantRef": "shop-01",
  "orderId": "ORDER-42",
  "orgName": "ИП Иванов",
  "phoneNumber": "77001234567",
  "paymentId": "123456",
  "type": "qr",
  "status": "Processed",
  "statusDesc": "Операция проведена успешно",
  "amount": 5000,
  "qrToken": "QR-TOKEN-...",
  "receiptUrl": "https://...",
  "orderNumber": "ORDER-001",
  "data": { ... },
  "timestamp": "2026-05-10T00:00:00.000Z"
}
```

| Поле | Тип | Описание |
|---|---|---|
| `event` | `string` | Название события (`payment.success`, `payment.failed`, `payment.expired`, `payment.lost`) |
| `merchantRef` | `string\|null` | Идентификатор мерчанта, переданный клиентом при создании платежа |
| `orderId` | `string\|null` | Идентификатор заказа, переданный клиентом при создании платежа |
| `orgName` | `string\|null` | Название организации из конверта на момент создания платежа |
| `phoneNumber` | `string\|null` | Телефон мерчанта из конверта на момент создания платежа |
| `paymentId` | `string` | ID платежа (QR operationId или invoice operationId) |
| `type` | `string` | Тип платежа: `qr` или `invoice` |
| `status` | `string` | Финальный статус от Kaspi API |
| `statusDesc` | `string` | Описание статуса |
| `amount` | `number\|null` | Сумма платежа в тенге |
| `qrToken` | `string\|null` | QR-токен (только для QR-платежей) |
| `receiptUrl` | `string\|null` | Ссылка на чек |
| `orderNumber` | `string\|null` | Номер заказа |
| `data` | `object` | Полные данные ответа от Kaspi API |
| `timestamp` | `string` | Время отправки уведомления (ISO 8601) |

### Подпись (HMAC)

Каждый запрос подписывается HMAC SHA-256 с использованием `secret` из конфигурации вебхука. Подпись передаётся в заголовке:

```
X-Webhook-Signature: sha256=<hex-digest>
```

**Проверка подписи на стороне получателя (Node.js):**

```javascript
import crypto from 'crypto';

const verifySignature = (body, signature, secret) => {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
};

// В обработчике запроса:
const rawBody = JSON.stringify(req.body); // или используйте raw body
const sig = req.headers['x-webhook-signature'];
if (!verifySignature(rawBody, sig, 'your-webhook-secret')) {
  return res.status(401).send('Invalid signature');
}
```

### Повторные попытки (Retry)

Если доставка вебхука не удалась (ошибка сети, таймаут, HTTP-ошибка), система выполняет до **3 попыток** с нарастающей задержкой:

| Попытка | Задержка |
|---|---|
| 1-я (первая) | Немедленно |
| 2-я | 5 секунд |
| 3-я | 30 секунд |

- Таймаут запроса: **10 секунд**.
- Очередь повторных попыток сохраняется в `webhook-retries.json` и переживает перезапуск сервера.
- После 3 неудачных попыток уведомление отбрасывается (логируется ошибка).

---

## Типичный сценарий использования

```
1. POST /api/auth/init              → получить onboardingState (создаётся устройство)
2. POST /api/auth/send-phone        → отправить SMS (onboardingState обновляется)
3. POST /api/auth/verify-otp        → подтвердить код → получить credentials → СОХРАНИТЬ

   Далее каждый запрос: -H "X-Kaspi-Credentials: <конверт>"

4. POST /api/qr/create              → создать QR для оплаты
5. GET  /api/qr/status              → проверить статус оплаты

   — или —

4. POST /api/invoice/create         → выставить счёт по номеру телефона
5. GET  /api/invoice/details        → проверить статус счёта

6. POST /api/refund/create          → возврат средств (при необходимости)
```

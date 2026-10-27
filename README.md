# 311 public BFF

NestJS HTTP-шлюз для PWA та Gravum backoffice. Працює в спільному workspace чотирьох репозиторіїв; початкова інструкція — `../311-server/README.md`.

## Контракти

- `/api/auth/*`: login, MFA, registration, session, account, email verification, password reset, logout.
- `/api/workspace`, `/api/commands`, `/api/jobs/:id/messages`, `/api/jobs/:id/photos/:photoId`: браузерна HttpOnly session cookie.
- `/api/backoffice/workspace`, `/api/backoffice/crew`, `/api/backoffice/commands` та messages/photos: короткоживучий bearer token `gravum:311` від ERP.
- POST `/api/commands` приймає `Idempotency-Key` UUID, `X-311-Request: 1` та `X-311-CSRF` із відповіді session/login.

Refresh/access tokens зберігаються зашифрованими AES-GCM у Redis, не повертаються браузерному PWA. Refresh серіалізований distributed lock. Production вимагає HTTPS origin, увімкненої авторизації та 32-byte session key. RPC запити обмежені timeout; повтор критичних команд контролюється ключем ідемпотентності на core.

Скопіюйте `.env.example` у `.env`. Не використовуйте однаковий RPC secret для core та pub. Зовнішній origin має точно відповідати адресі PWA; CORS і Origin не допускають wildcard. Core RPC та брокер повинні залишатися в приватній мережі.

`npm start -w 311-pub-server` — із кореня workspace після збірки. Автоматичні HTTP/security тести знаходяться в `311-server/test/http-security.test.cjs`.

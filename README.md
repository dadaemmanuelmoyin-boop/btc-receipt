# btc-receipt

Transfer confirmation screen (mobile-first) + Express/Postgres API.

## Setup
```bash
npm install
cp .env.example .env     # fill values, then: export $(cat .env | xargs)
npm run migrate
npm start
```
Open `http://localhost:3000/?id=<transaction-uuid>`. The page reads a JWT (HS256, `sub` = user UUID) from `sessionStorage.token`; set it from your login flow.

## Seed + try it
```sql
INSERT INTO transactions (id, sender_id, recipient_id, recipient_cashtag, fiat_amount_cents)
VALUES ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','$thalihector',250000);
```
```bash
TOKEN=$(node -e "console.log(require('jsonwebtoken').sign({sub:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'},process.env.JWT_SECRET))")
curl -H "Authorization: Bearer $TOKEN" localhost:3000/api/transactions/11111111-1111-4111-8111-111111111111

# Signed webhook (replay the same eventId: second call returns replay:true, no double transition)
BODY='{"eventId":"evt_1","transactionId":"11111111-1111-4111-8111-111111111111","status":"completed"}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -hex | sed 's/^.* //')
curl -X POST localhost:3000/api/webhooks/payment-status -H "Content-Type: application/json" \
     -H "X-Timestamp: $TS" -H "X-Signature: $SIG" -d "$BODY"
```
The open page flips from Pending to "View receipt" within one poll interval, and the change is announced via `aria-live`.

## Design notes
- **Authorization**: only `sender_id` / `recipient_id` can read or refresh; non-participants get the same 404 as a missing ID.
- **Atomicity**: all status changes go through `applyStatus` (`UPDATE … WHERE status='pending'`), so terminal states never revert.
- **Idempotency**: webhooks dedupe on `eventId`; refresh requires an `Idempotency-Key`. Claims share the DB transaction, so a failure rolls back and the provider's retry succeeds.
- **Notifications**: written to `notification_outbox` in the same transaction; run a worker that sends rows where `sent_at IS NULL`.
- **Provider hook**: implement `fetchProviderStatus` in `server.js`.
- **Not included**: transfer creation, login, rate limiting (add `express-rate-limit` before production), and the `/receipt.html` detail screen.

## Website
`npm run migrate` now also applies `db/002_website.sql` (users, idempotent transfer creation).

Pages: `/` (sign in / create account, send form, activity list) and `/transfer.html?id=…` (the status screen).
Flow: register two accounts → send from one to the other's cashtag → the status screen opens in **Pending** and flips when your payment provider's signed webhook reports `completed`.

Deploy (Render, Railway, Fly, any Node host): set `DATABASE_URL`, `JWT_SECRET`, `WEBHOOK_SECRET`, run `npm run migrate` once, start with `npm start`, and serve over HTTPS only. Point the provider's webhook at `https://<your-domain>/api/webhooks/payment-status`.
Before launch: swap in-memory rate limiting for a shared store, store the token in an httpOnly cookie if you want stronger XSS resistance, and complete the provider integration + any money-transmission/KYC requirements for your jurisdiction.

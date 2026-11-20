CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE tx_status AS ENUM ('pending','completed','failed','cancelled');

CREATE TABLE transactions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id          UUID NOT NULL,
  recipient_id       UUID,                       -- set when recipient is a platform user (used for authorization)
  recipient_cashtag  VARCHAR(40) NOT NULL,
  fiat_amount_cents  INTEGER NOT NULL CHECK (fiat_amount_cents > 0),
  currency           VARCHAR(3)  NOT NULL DEFAULT 'USD',
  asset              VARCHAR(10) NOT NULL DEFAULT 'BTC',
  status             tx_status   NOT NULL DEFAULT 'pending',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX transactions_sender_idx    ON transactions (sender_id);
CREATE INDEX transactions_recipient_idx ON transactions (recipient_id);

-- Replay protection for webhooks (provider event id) and client mutations (Idempotency-Key)
CREATE TABLE processed_events (
  scope      TEXT NOT NULL,          -- 'webhook' | 'refresh:<userId>'
  event_key  TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, event_key)
);

-- Transactional outbox: a worker sends notifications, so a crash can't lose or duplicate them
CREATE TABLE notification_outbox (
  id             BIGSERIAL PRIMARY KEY,
  transaction_id UUID NOT NULL REFERENCES transactions(id),
  kind           TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at        TIMESTAMPTZ,
  UNIQUE (transaction_id, kind)
);

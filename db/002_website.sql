CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cashtag       VARCHAR(20) NOT NULL,            -- stored lowercase, no leading $
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_cashtag_idx ON users (cashtag);

ALTER TABLE transactions ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX transactions_idem_idx ON transactions (sender_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

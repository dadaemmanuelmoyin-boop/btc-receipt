import crypto from 'node:crypto';
import express from 'express';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { mountSite } from './routes_site.js';

const { PORT = 3000, DATABASE_URL, JWT_SECRET, WEBHOOK_SECRET, WEBHOOK_TOLERANCE_SEC = 300 } = process.env;
const missing = ['DATABASE_URL', 'JWT_SECRET', 'WEBHOOK_SECRET'].filter((k) => !process.env[k]);
if (missing.length) throw new Error(`Missing environment variables: ${missing.join(', ')}. Add them in Vercel > Project > Settings > Environment Variables, then redeploy.`);

// Serverless-friendly pool: few connections, TLS for hosted Postgres (Neon, Supabase, etc.)
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  max: process.env.VERCEL ? 3 : 10,
  ssl: process.env.VERCEL || /sslmode=require/.test(DATABASE_URL) ? { rejectUnauthorized: false } : undefined,
});
const app = express();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const STATUSES = ['pending', 'completed', 'failed', 'cancelled'];
const TERMINAL = new Set(['completed', 'failed', 'cancelled']);

// ---------- helpers ----------
const fmtMoney = (cents, currency) =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency, maximumFractionDigits: cents % 100 ? 2 : 0 }).format(cents / 100);

const toReceipt = (t) => ({
  id: t.id,
  recipientCashtag: t.recipient_cashtag,
  formattedAmount: fmtMoney(t.fiat_amount_cents, t.currency),
  asset: t.asset === 'BTC' ? 'bitcoin' : t.asset,
  status: t.status,
  updatedAt: t.updated_at,
});

// ---------- auth ----------
function requireAuth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  try {
    req.user = jwt.verify(m?.[1] ?? '', JWT_SECRET, { algorithms: ['HS256'] }); // req.user.sub = user UUID
    return next();
  } catch {
    return res.status(401).json({ error: 'unauthenticated' });
  }
}

// Returns the row only if the caller is sender or recipient. Non-participants get the same 404 as a missing id,
// so IDs can't be probed.
async function loadForParticipant(db, id, userId, { lock = false } = {}) {
  if (!UUID.test(id)) return null;
  const { rows } = await db.query(
    `SELECT * FROM transactions WHERE id = $1 AND (sender_id = $2 OR recipient_id = $2) ${lock ? 'FOR UPDATE' : ''}`,
    [id, userId]);
  return rows[0] ?? null;
}

// ---------- state machine (single place that mutates status) ----------
// Only pending -> terminal is allowed. The conditional UPDATE makes it atomic and race-safe.
async function applyStatus(db, txId, next) {
  if (!STATUSES.includes(next) || next === 'pending') return { changed: false };
  const { rows } = await db.query(
    `UPDATE transactions SET status = $2, updated_at = now() WHERE id = $1 AND status = 'pending' RETURNING *`,
    [txId, next]);
  if (!rows[0]) return { changed: false };
  if (next === 'completed') {
    await db.query(
      `INSERT INTO notification_outbox (transaction_id, kind) VALUES ($1, 'transfer_completed') ON CONFLICT DO NOTHING`,
      [txId]);
  }
  return { changed: true, row: rows[0] };
}

// Claim an idempotency key inside the caller's DB transaction. Returns false on replay.
async function claimKey(db, scope, key) {
  const { rowCount } = await db.query(
    `INSERT INTO processed_events (scope, event_key) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [scope, key]);
  return rowCount === 1;
}

async function inTx(fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

// Replace with your payment provider's status lookup.
async function fetchProviderStatus(/* tx */) { return 'pending'; }

// ---------- webhook (raw body needed for signature) ----------
app.post('/api/webhooks/payment-status', express.raw({ type: 'application/json', limit: '32kb' }), async (req, res) => {
  const ts = req.get('x-timestamp') || '';
  const sig = req.get('x-signature') || '';
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(`${ts}.`).update(req.body).digest('hex');
  const a = Buffer.from(sig, 'hex'), b = Buffer.from(expected, 'hex');
  const fresh = Math.abs(Date.now() / 1000 - Number(ts)) <= Number(WEBHOOK_TOLERANCE_SEC);
  if (!fresh || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'bad_signature' });

  let evt;
  try { evt = JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).json({ error: 'bad_json' }); }
  if (!evt?.eventId || !UUID.test(evt.transactionId ?? '') || !STATUSES.includes(evt.status)) {
    return res.status(400).json({ error: 'bad_payload' });
  }

  try {
    const result = await inTx(async (db) => {
      if (!(await claimKey(db, 'webhook', String(evt.eventId)))) return { replay: true };
      return applyStatus(db, evt.transactionId, evt.status);
    });
    return res.status(200).json({ ok: true, replay: !!result.replay, changed: !!result.changed }); // 200 on replay stops provider retries
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' }); // provider retries; claim was rolled back
  }
});

app.use(express.json({ limit: '8kb' }));
app.set('trust proxy', 1);
app.use(express.static(new URL('./public', import.meta.url).pathname));

const signToken = (sub) => jwt.sign({ sub }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
mountSite({ app, pool, requireAuth, signToken, toReceipt });

// ---------- receipt ----------
app.get('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    const tx = await loadForParticipant(pool, req.params.id, req.user.sub);
    if (!tx) return res.status(404).json({ error: 'not_found' });
    res.set('Cache-Control', 'no-store');
    return res.json(toReceipt(tx));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Manual refresh: asks the provider, then applies via the same state machine. Requires Idempotency-Key.
app.post('/api/transactions/:id/refresh', requireAuth, async (req, res) => {
  const key = req.get('idempotency-key');
  if (!key || key.length > 128) return res.status(400).json({ error: 'idempotency_key_required' });
  try {
    const out = await inTx(async (db) => {
      const tx = await loadForParticipant(db, req.params.id, req.user.sub, { lock: true });
      if (!tx) return null;
      if (TERMINAL.has(tx.status)) return tx;
      if (!(await claimKey(db, `refresh:${req.user.sub}`, key))) return tx; // replay: return current state
      const next = await fetchProviderStatus(tx);
      const r = await applyStatus(db, tx.id, next);
      return r.row ?? tx;
    });
    if (!out) return res.status(404).json({ error: 'not_found' });
    return res.json(toReceipt(out));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

if (!process.env.VERCEL) app.listen(PORT, () => console.log(`listening on :${PORT}`));
export { app };
export default app; // Vercel uses the default export as the request handler

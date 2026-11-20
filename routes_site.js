import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(crypto.scrypt);

const hash = async (pw) => {
  const salt = crypto.randomBytes(16);
  return `${salt.toString('hex')}:${(await scrypt(pw, salt, 64)).toString('hex')}`;
};
const verify = async (pw, stored) => {
  const [s, h] = stored.split(':');
  const got = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  const want = Buffer.from(h, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
};

// Tiny in-memory limiter for auth routes (use Redis/express-rate-limit behind multiple instances)
const hits = new Map();
const limited = (req, res, next) => {
  const k = req.ip, now = Date.now();
  const arr = (hits.get(k) || []).filter((t) => now - t < 60_000);
  arr.push(now); hits.set(k, arr);
  return arr.length > 10 ? res.status(429).json({ error: 'too_many_attempts' }) : next();
};

const TAG = /^[a-z0-9_]{3,20}$/;
const norm = (s) => String(s ?? '').trim().replace(/^\$/, '').toLowerCase();
const MIN_CENTS = 100, MAX_CENTS = 1_000_000; // $1 to $10,000 per transfer

export function mountSite({ app, pool, requireAuth, signToken, toReceipt }) {
  app.post('/api/auth/register', limited, async (req, res) => {
    const tag = norm(req.body?.cashtag), pw = String(req.body?.password ?? '');
    if (!TAG.test(tag)) return res.status(400).json({ error: 'invalid_cashtag' });
    if (pw.length < 10 || pw.length > 200) return res.status(400).json({ error: 'weak_password' });
    try {
      const { rows } = await pool.query(
        'INSERT INTO users (cashtag, password_hash) VALUES ($1,$2) RETURNING id, cashtag', [tag, await hash(pw)]);
      return res.status(201).json({ token: signToken(rows[0].id), cashtag: `$${rows[0].cashtag}` });
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'cashtag_taken' });
      console.error(e); return res.status(500).json({ error: 'server_error' });
    }
  });

  app.post('/api/auth/login', limited, async (req, res) => {
    const tag = norm(req.body?.cashtag), pw = String(req.body?.password ?? '');
    const { rows } = await pool.query('SELECT id, cashtag, password_hash FROM users WHERE cashtag=$1', [tag]);
    // Always run a hash comparison so timing doesn't reveal whether the account exists
    const ok = await verify(pw, rows[0]?.password_hash ?? `${'0'.repeat(32)}:${'0'.repeat(128)}`);
    if (!rows[0] || !ok) return res.status(401).json({ error: 'invalid_credentials' });
    return res.json({ token: signToken(rows[0].id), cashtag: `$${rows[0].cashtag}` });
  });

  // One-step entry: signs in if the cashtag exists, otherwise creates the account.
  app.post('/api/auth/continue', limited, async (req, res) => {
    const tag = norm(req.body?.cashtag), pw = String(req.body?.password ?? '');
    if (!TAG.test(tag)) return res.status(400).json({ error: 'invalid_cashtag' });
    try {
      const { rows } = await pool.query('SELECT id, cashtag, password_hash FROM users WHERE cashtag=$1', [tag]);
      if (rows[0]) {
        if (!(await verify(pw, rows[0].password_hash))) return res.status(401).json({ error: 'invalid_credentials' });
        return res.json({ token: signToken(rows[0].id), cashtag: `$${rows[0].cashtag}`, created: false });
      }
      if (pw.length < 10 || pw.length > 200) return res.status(400).json({ error: 'weak_password' });
      const ins = await pool.query('INSERT INTO users (cashtag, password_hash) VALUES ($1,$2) RETURNING id, cashtag', [tag, await hash(pw)]);
      return res.status(201).json({ token: signToken(ins.rows[0].id), cashtag: `$${ins.rows[0].cashtag}`, created: true });
    } catch (e) {
      if (e.code === '23505') return res.status(401).json({ error: 'invalid_credentials' }); // lost a signup race
      console.error(e); return res.status(500).json({ error: 'server_error' });
    }
  });

  // Create a transfer. Recipient must be a registered user; status starts 'pending' and only the
  // signed payment webhook can move it forward.
  app.post('/api/transactions', requireAuth, async (req, res) => {
    const key = req.get('idempotency-key');
    if (!key || key.length > 128) return res.status(400).json({ error: 'idempotency_key_required' });
    const tag = norm(req.body?.recipientCashtag), cents = Number(req.body?.amountCents);
    if (!TAG.test(tag)) return res.status(400).json({ error: 'invalid_recipient' });
    if (!Number.isInteger(cents) || cents < MIN_CENTS || cents > MAX_CENTS) return res.status(400).json({ error: 'invalid_amount' });
    try {
      const { rows: [rcpt] } = await pool.query('SELECT id, cashtag FROM users WHERE cashtag=$1', [tag]);
      if (!rcpt) return res.status(404).json({ error: 'recipient_not_found' });
      if (rcpt.id === req.user.sub) return res.status(400).json({ error: 'cannot_send_to_self' });
      await pool.query(
        `INSERT INTO transactions (sender_id, recipient_id, recipient_cashtag, fiat_amount_cents, idempotency_key)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (sender_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`,
        [req.user.sub, rcpt.id, `$${rcpt.cashtag}`, cents, key]);
      const { rows: [tx] } = await pool.query(
        'SELECT * FROM transactions WHERE sender_id=$1 AND idempotency_key=$2', [req.user.sub, key]);
      return res.status(201).json(toReceipt(tx));
    } catch (e) { console.error(e); return res.status(500).json({ error: 'server_error' }); }
  });

  app.get('/api/transactions', requireAuth, async (req, res) => {
    const { rows } = await pool.query(
      `SELECT * FROM transactions WHERE sender_id=$1 OR recipient_id=$1 ORDER BY created_at DESC LIMIT 25`, [req.user.sub]);
    res.set('Cache-Control', 'no-store');
    return res.json(rows.map(toReceipt));
  });
}

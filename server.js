import dotenv from 'dotenv';
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || '.env.local' });

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import pg from 'pg';
import { attachDatabasePool } from '@vercel/functions';
import { neon } from '@neondatabase/serverless';
import { S3Client, HeadBucketCommand } from '@aws-sdk/client-s3';
import { createDraw } from './lib/draw.js';
import { createOpaqueToken, decryptToken, encryptToken, hashToken, secretsMatch } from './lib/security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, 'public');
const app = express();
const sql = neon(process.env.DATABASE_URL);
const pgConnectionString = String(process.env.DATABASE_URL || '').replace('sslmode=require', 'sslmode=verify-full');
const pool = new pg.Pool({ connectionString: pgConnectionString, max: 5 });
if (process.env.VERCEL) attachDatabasePool(pool);

const exchangeId = process.env.EXCHANGE_ID || '00000000-0000-4000-8000-000000000001';
const port = Number(process.env.PORT || 4173);
const sessionCookie = 'lovefeast_admin';
const sessionHours = 8;

app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(publicDir));

function normalizePhone(value) {
  let phone = String(value || '').replace(/[\s().-]/g, '');
  if (/^0[789]\d{9}$/.test(phone)) phone = '+234' + phone.slice(1);
  if (/^234[789]\d{9}$/.test(phone)) phone = '+' + phone;
  return phone;
}

function cookieValue(req, name) {
  const item = String(req.get('cookie') || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : '';
}

function setSessionCookie(res, token, maxAge = sessionHours * 60 * 60) {
  const secure = process.env.VERCEL || process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${sessionCookie}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure ? '; Secure' : ''}`);
}

function sameOriginOnly(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();
  const forwardedHost = req.get('x-forwarded-host') || req.get('host');
  try {
    if (new URL(origin).host !== forwardedHost) return res.status(403).json({ error: 'Request origin is not allowed.' });
  } catch {
    return res.status(403).json({ error: 'Request origin is not allowed.' });
  }
  next();
}

async function adminOnly(req, res, next) {
  const rawToken = cookieValue(req, sessionCookie);
  if (!rawToken) return res.status(401).json({ error: 'Organizer sign-in required.' });
  try {
    const [session] = await sql`UPDATE organizer_sessions SET last_seen_at = now() WHERE token_hash = ${hashToken(rawToken)} AND revoked_at IS NULL AND expires_at > now() RETURNING id`;
    if (!session) return res.status(401).json({ error: 'Your organizer session has expired. Please sign in again.' });
    req.organizerSessionId = session.id;
    next();
  } catch {
    res.status(500).json({ error: 'Unable to verify organizer access.' });
  }
}

async function audit(action, metadata = {}) {
  await sql`INSERT INTO audit_events (id, exchange_id, action, metadata) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${action}, ${JSON.stringify(metadata)})`;
}

async function auditWithClient(client, action, metadata = {}) {
  await client.query('INSERT INTO audit_events (id, exchange_id, action, metadata) VALUES ($1, $2, $3, $4::jsonb)', [crypto.randomUUID(), exchangeId, action, JSON.stringify(metadata)]);
}

function requireLinkSecret(res) {
  const secret = process.env.LINK_ENCRYPTION_SECRET;
  if (!secret || secret.length < 32) {
    res.status(503).json({ error: 'Private-link encryption is not configured.' });
    return null;
  }
  return secret;
}

app.get('/api/event', async (_req, res) => {
  try {
    const [event] = await sql`SELECT id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn FROM exchanges WHERE id = ${exchangeId}`;
    if (!event) return res.status(404).json({ error: 'Event not found.' });
    res.json(event);
  } catch {
    res.status(500).json({ error: 'Unable to load the event.' });
  }
});

app.post('/api/admin/login', sameOriginOnly, async (req, res) => {
  const configuredPassword = process.env.ORGANIZER_PASSWORD;
  const candidate = String(req.body.password || '');
  if (!configuredPassword || !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    return res.status(503).json({ error: 'Organizer authentication is not configured.' });
  }
  const ipHash = hashToken(`${process.env.SESSION_SECRET}:${req.ip || 'unknown'}`);
  try {
    const [attempts] = await sql`SELECT count(*)::int AS count FROM organizer_login_attempts WHERE ip_hash = ${ipHash} AND succeeded = false AND attempted_at > now() - interval '15 minutes'`;
    if (attempts.count >= 5) return res.status(429).json({ error: 'Too many sign-in attempts. Please wait 15 minutes and try again.' });
    const succeeded = secretsMatch(candidate, configuredPassword);
    await sql`INSERT INTO organizer_login_attempts (id, ip_hash, succeeded) VALUES (${crypto.randomUUID()}, ${ipHash}, ${succeeded})`;
    if (!succeeded) return res.status(401).json({ error: 'The organizer password is incorrect.' });

    const token = createOpaqueToken();
    await sql`INSERT INTO organizer_sessions (id, exchange_id, token_hash, expires_at) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${hashToken(token)}, now() + (${sessionHours} * interval '1 hour'))`;
    await sql`DELETE FROM organizer_login_attempts WHERE ip_hash = ${ipHash} OR attempted_at < now() - interval '1 day'`;
    await audit('organizer_signed_in');
    setSessionCookie(res, token);
    res.json({ authenticated: true });
  } catch {
    res.status(500).json({ error: 'Unable to sign in right now.' });
  }
});

app.post('/api/admin/logout', sameOriginOnly, adminOnly, async (req, res) => {
  try {
    await sql`UPDATE organizer_sessions SET revoked_at = now() WHERE id = ${req.organizerSessionId}`;
    setSessionCookie(res, '', 0);
    res.status(204).end();
  } catch {
    res.status(500).json({ error: 'Unable to sign out.' });
  }
});

app.use('/api/admin', (req, res, next) => {
  if (req.path === '/login') return next();
  return adminOnly(req, res, next);
});
app.use('/api/admin', sameOriginOnly);

app.get('/api/admin/state', async (_req, res) => {
  const linkSecret = requireLinkSecret(res);
  if (!linkSecret) return;
  try {
    const [event] = await sql`SELECT id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn FROM exchanges WHERE id = ${exchangeId}`;
    const roster = await sql`SELECT id, normalized_phone, display_name, EXISTS (SELECT 1 FROM participants p WHERE p.eligible_member_id = eligible_members.id) AS registered FROM eligible_members WHERE exchange_id = ${exchangeId} ORDER BY display_name`;
    const participants = await sql`SELECT id, display_name, normalized_phone, commitment_accepted_at, registered_at FROM participants WHERE exchange_id = ${exchangeId} ORDER BY registered_at`;
    const storedLinks = event?.is_drawn ? await sql`
      SELECT p.id AS participant_id, p.display_name AS participant_name, t.id AS token_id, t.token_ciphertext, t.viewed_at, t.expires_at
      FROM participants p
      LEFT JOIN LATERAL (
        SELECT id, token_ciphertext, viewed_at, expires_at
        FROM reveal_tokens
        WHERE participant_id = p.id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
        ORDER BY created_at DESC LIMIT 1
      ) t ON true
      WHERE p.exchange_id = ${exchangeId}
      ORDER BY p.registered_at` : [];
    const links = storedLinks.map(link => {
      let token = null;
      if (link.token_ciphertext) {
        try { token = decryptToken(link.token_ciphertext, linkSecret); } catch { token = null; }
      }
      return { participantId: link.participant_id, participantName: link.participant_name, tokenId: link.token_id, token, viewedAt: link.viewed_at, expiresAt: link.expires_at };
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ event, roster, participants, links });
  } catch {
    res.status(500).json({ error: 'Unable to load organizer state.' });
  }
});

app.patch('/api/admin/event', async (req, res) => {
  const { title, fellowship, description, guidance, cutoffDate, exchangeDate } = req.body;
  if (!title || !fellowship || !cutoffDate || !exchangeDate) return res.status(400).json({ error: 'Title, fellowship, cutoff and exchange date are required.' });
  try {
    const [event] = await sql`UPDATE exchanges SET title = ${title.trim()}, fellowship = ${fellowship.trim()}, description = ${String(description || '').trim()}, guidance = ${String(guidance || '').trim()}, cutoff_at = ${cutoffDate}, exchange_at = ${exchangeDate}, updated_at = now() WHERE id = ${exchangeId} RETURNING id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn`;
    await audit('event_updated');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'Unable to update event.' });
  }
});

app.post('/api/admin/roster', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const name = String(req.body.name || 'Unnamed member').trim();
  if (!/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid Nigerian phone number.' });
  try {
    const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id, normalized_phone, display_name`;
    if (!member) return res.status(409).json({ error: 'That number is already on the roster.' });
    await audit('roster_member_added');
    res.status(201).json(member);
  } catch {
    res.status(500).json({ error: 'Unable to add roster member.' });
  }
});

app.post('/api/admin/roster/import', async (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows.slice(0, 500) : [];
  let added = 0;
  const invalid = [];
  try {
    for (const row of rows) {
      const phone = normalizePhone(row.phone);
      const name = String(row.name || 'Unnamed member').trim();
      if (!/^\+234[789]\d{9}$/.test(phone)) {
        invalid.push({ phone: row.phone, reason: 'Invalid Nigerian number' });
        continue;
      }
      const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id`;
      if (member) added += 1;
    }
    await audit('roster_imported', { added, invalid: invalid.length });
    res.json({ added, invalid });
  } catch {
    res.status(500).json({ error: 'Unable to import the roster.' });
  }
});

app.delete('/api/admin/roster/:id', async (req, res) => {
  try {
    const [member] = await sql`DELETE FROM eligible_members WHERE id = ${req.params.id} AND exchange_id = ${exchangeId} AND NOT EXISTS (SELECT 1 FROM participants WHERE eligible_member_id = eligible_members.id) RETURNING id`;
    if (!member) return res.status(409).json({ error: 'That member is registered or cannot be removed.' });
    await audit('roster_member_removed');
    res.status(204).end();
  } catch {
    res.status(500).json({ error: 'Unable to remove roster member.' });
  }
});

app.post('/api/admin/close', async (_req, res) => {
  try {
    const [event] = await sql`UPDATE exchanges SET is_open = false, is_closed = true, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`;
    if (!event) return res.status(409).json({ error: 'A completed draw cannot be changed.' });
    await audit('registration_closed');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'Unable to close registration.' });
  }
});

app.post('/api/admin/reopen', async (_req, res) => {
  try {
    const [event] = await sql`UPDATE exchanges SET is_open = true, is_closed = false, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`;
    if (!event) return res.status(409).json({ error: 'A completed draw cannot be reopened.' });
    await audit('registration_reopened');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'Unable to reopen registration.' });
  }
});

app.post('/api/register', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const name = String(req.body.name || '').trim().slice(0, 120);
  if (!name || !req.body.commitmentAccepted || !/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'We couldn’t complete that registration. Please check your details or contact the organizer.' });
  try {
    const [participant] = await sql`INSERT INTO participants (id, exchange_id, eligible_member_id, display_name, normalized_phone, commitment_accepted_at)
      SELECT ${crypto.randomUUID()}, e.id, m.id, ${name}, m.normalized_phone, now() FROM exchanges e JOIN eligible_members m ON m.exchange_id = e.id AND m.normalized_phone = ${phone}
      WHERE e.id = ${exchangeId} AND e.is_open = true AND e.is_closed = false AND now() < e.cutoff_at
      AND NOT EXISTS (SELECT 1 FROM participants p WHERE p.exchange_id = e.id AND p.normalized_phone = m.normalized_phone)
      RETURNING id, display_name, registered_at`;
    if (!participant) return res.status(400).json({ error: 'We couldn’t complete that registration. Please check your details or contact the organizer.' });
    await audit('participant_registered');
    res.status(201).json({ participant });
  } catch {
    res.status(500).json({ error: 'Unable to complete registration.' });
  }
});

app.post('/api/admin/draw', async (_req, res) => {
  const linkSecret = requireLinkSecret(res);
  if (!linkSecret) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const eventResult = await client.query('SELECT is_closed, is_drawn FROM exchanges WHERE id = $1 FOR UPDATE', [exchangeId]);
    const event = eventResult.rows[0];
    if (!event?.is_closed || event.is_drawn) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Registration must be closed and the draw must not already exist.' });
    }
    const participantResult = await client.query('SELECT id, display_name FROM participants WHERE exchange_id = $1 ORDER BY registered_at FOR UPDATE', [exchangeId]);
    if (participantResult.rows.length < 2) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'At least two participants are required.' });
    }

    const assignments = createDraw(participantResult.rows);
    const links = [];
    for (const { giver, recipient } of assignments) {
      const rawToken = createOpaqueToken();
      await client.query('INSERT INTO assignments (id, exchange_id, giver_participant_id, recipient_participant_id) VALUES ($1, $2, $3, $4)', [crypto.randomUUID(), exchangeId, giver.id, recipient.id]);
      await client.query(`INSERT INTO reveal_tokens (id, exchange_id, participant_id, token_hash, token_ciphertext, expires_at)
        SELECT $1, $2, $3, $4, $5, (exchange_at::timestamp AT TIME ZONE 'Africa/Lagos') + interval '8 days' FROM exchanges WHERE id = $2`,
        [crypto.randomUUID(), exchangeId, giver.id, hashToken(rawToken), encryptToken(rawToken, linkSecret)]);
      links.push({ participantId: giver.id, participantName: giver.display_name, token: rawToken });
    }
    await client.query('UPDATE exchanges SET is_drawn = true, updated_at = now() WHERE id = $1', [exchangeId]);
    await auditWithClient(client, 'draw_completed', { participants: assignments.length });
    await client.query('COMMIT');
    res.json({ links });
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Unable to complete the draw. No assignments were saved.' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/reveal/:participantId/regenerate', async (req, res) => {
  const linkSecret = requireLinkSecret(res);
  if (!linkSecret) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const participantResult = await client.query(`SELECT p.id, p.display_name FROM participants p
      JOIN assignments a ON a.giver_participant_id = p.id
      JOIN exchanges e ON e.id = p.exchange_id
      WHERE p.id = $1 AND p.exchange_id = $2 AND e.is_drawn = true FOR UPDATE`, [req.params.participantId, exchangeId]);
    const participant = participantResult.rows[0];
    if (!participant) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Participant assignment not found.' });
    }
    await client.query('UPDATE reveal_tokens SET revoked_at = now() WHERE participant_id = $1 AND revoked_at IS NULL', [participant.id]);
    const rawToken = createOpaqueToken();
    const tokenId = crypto.randomUUID();
    await client.query(`INSERT INTO reveal_tokens (id, exchange_id, participant_id, token_hash, token_ciphertext, expires_at)
      SELECT $1, $2, $3, $4, $5, (exchange_at::timestamp AT TIME ZONE 'Africa/Lagos') + interval '8 days' FROM exchanges WHERE id = $2`,
      [tokenId, exchangeId, participant.id, hashToken(rawToken), encryptToken(rawToken, linkSecret)]);
    await auditWithClient(client, 'reveal_link_regenerated', { participantId: participant.id });
    await client.query('COMMIT');
    res.json({ participantId: participant.id, participantName: participant.display_name, tokenId, token: rawToken });
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Unable to replace the private link.' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/reveal/:participantId/revoke', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`UPDATE reveal_tokens SET revoked_at = now()
      WHERE participant_id = $1 AND exchange_id = $2 AND revoked_at IS NULL RETURNING id`, [req.params.participantId, exchangeId]);
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'No active private link was found.' });
    }
    await auditWithClient(client, 'reveal_link_revoked', { participantId: req.params.participantId });
    await client.query('COMMIT');
    res.status(204).end();
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Unable to revoke the private link.' });
  } finally {
    client.release();
  }
});

app.post('/api/reveal', sameOriginOnly, async (req, res) => {
  const rawToken = String(req.body.token || '');
  if (!rawToken || rawToken.length > 100) return res.status(404).json({ error: 'This private reveal link is invalid or has expired.' });
  try {
    const tokenHash = hashToken(rawToken);
    const [result] = await sql`SELECT p.display_name AS participant_name, recipient.display_name AS recipient_name, e.guidance
      FROM reveal_tokens t
      JOIN participants p ON p.id = t.participant_id
      JOIN assignments a ON a.giver_participant_id = p.id
      JOIN participants recipient ON recipient.id = a.recipient_participant_id
      JOIN exchanges e ON e.id = t.exchange_id
      WHERE t.token_hash = ${tokenHash} AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())`;
    if (!result) return res.status(404).json({ error: 'This private reveal link is invalid or has expired.' });
    await sql`UPDATE reveal_tokens SET viewed_at = COALESCE(viewed_at, now()) WHERE token_hash = ${tokenHash}`;
    res.setHeader('Cache-Control', 'no-store');
    res.json(result);
  } catch {
    res.status(500).json({ error: 'Unable to load this reveal.' });
  }
});

app.get('/api/storage/health', async (_req, res) => {
  if (!process.env.AWS_ENDPOINT_URL_S3 || !process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) return res.status(503).json({ configured: false });
  try {
    const client = new S3Client({ endpoint: process.env.AWS_ENDPOINT_URL_S3, region: process.env.AWS_REGION || 'eu-central-1', forcePathStyle: true });
    await client.send(new HeadBucketCommand({ Bucket: process.env.S3_BUCKET || 'assets' }));
    res.json({ configured: true, bucket: process.env.S3_BUCKET || 'assets' });
  } catch {
    res.status(502).json({ configured: true, reachable: false, error: 'Storage service could not be reached.' });
  }
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

if (!process.env.VERCEL) app.listen(port, () => console.log(`Love Feast running at http://localhost:${port}`));

export default app;

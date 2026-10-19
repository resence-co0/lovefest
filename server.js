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
const eventTimeZone = 'Africa/Lagos';
// DATE is returned as text so it never shifts with the server's local timezone.
const eventColumns = sql.unsafe("id, title, fellowship, description, guidance, cutoff_at, to_char(exchange_at, 'YYYY-MM-DD') AS exchange_at, is_open, is_closed, is_drawn");

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
app.use((req, _res, next) => { req.body ??= {}; next(); });
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
    if (new URL(origin).host !== forwardedHost) return res.status(403).json({ error: 'This request came from another website and was blocked. Please use the Love Feast site directly.' });
  } catch {
    return res.status(403).json({ error: 'This request came from another website and was blocked. Please use the Love Feast site directly.' });
  }
  next();
}

async function findOrganizerSession(req) {
  const rawToken = cookieValue(req, sessionCookie);
  if (!rawToken) return null;
  const [session] = await sql`UPDATE organizer_sessions SET last_seen_at = now() WHERE token_hash = ${hashToken(rawToken)} AND revoked_at IS NULL AND expires_at > now() RETURNING id`;
  return session || null;
}

async function adminOnly(req, res, next) {
  if (!cookieValue(req, sessionCookie)) return res.status(401).json({ error: 'Please sign in as the organizer to continue.' });
  try {
    const session = await findOrganizerSession(req);
    if (!session) return res.status(401).json({ error: 'Your organizer session has expired. Please sign in again.' });
    req.organizerSessionId = session.id;
    next();
  } catch {
    res.status(500).json({ error: 'We couldn’t check your organizer sign-in. Please try again in a moment.' });
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
    res.status(503).json({ error: 'Private links aren’t set up on this server yet. Set LINK_ENCRYPTION_SECRET in the deployment settings.' });
    return null;
  }
  return secret;
}

app.get('/api/event', async (_req, res) => {
  try {
    const [event] = await sql`SELECT ${eventColumns} FROM exchanges WHERE id = ${exchangeId}`;
    if (!event) return res.status(404).json({ error: 'This exchange couldn’t be found. Please contact the organizer.' });
    res.json(event);
  } catch {
    res.status(500).json({ error: 'We couldn’t load the exchange details. Please try again in a moment.' });
  }
});

app.post('/api/admin/login', sameOriginOnly, async (req, res) => {
  const configuredPassword = process.env.ORGANIZER_PASSWORD;
  const candidate = String(req.body.password || '');
  if (!configuredPassword || !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    return res.status(503).json({ error: 'Organizer sign-in isn’t set up on this server yet. Set ORGANIZER_PASSWORD and SESSION_SECRET in the deployment settings.' });
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
    res.status(500).json({ error: 'We couldn’t sign you in right now. Please try again in a moment.' });
  }
});

app.post('/api/admin/logout', sameOriginOnly, adminOnly, async (req, res) => {
  try {
    await sql`UPDATE organizer_sessions SET revoked_at = now() WHERE id = ${req.organizerSessionId}`;
    setSessionCookie(res, '', 0);
    res.status(204).end();
  } catch {
    res.status(500).json({ error: 'We couldn’t sign you out. Please try again in a moment.' });
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
    const [event] = await sql`SELECT ${eventColumns} FROM exchanges WHERE id = ${exchangeId}`;
    const roster = await sql`SELECT id, normalized_phone, display_name, EXISTS (SELECT 1 FROM participants p WHERE p.eligible_member_id = eligible_members.id) AS registered FROM eligible_members WHERE exchange_id = ${exchangeId} ORDER BY display_name`;
    const participants = await sql`SELECT id, display_name, normalized_phone, gift_hint, status, commitment_accepted_at, registered_at FROM participants WHERE exchange_id = ${exchangeId} ORDER BY registered_at`;
    const storedLinks = event?.is_drawn ? await sql`
      SELECT p.id AS participant_id, p.display_name AS participant_name, p.normalized_phone, t.id AS token_id, t.token_ciphertext, t.viewed_at, t.expires_at
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
      return { participantId: link.participant_id, participantName: link.participant_name, phone: link.normalized_phone, tokenId: link.token_id, token, viewedAt: link.viewed_at, expiresAt: link.expires_at };
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ event, roster, participants, links });
  } catch {
    res.status(500).json({ error: 'We couldn’t load the organizer workspace. Please try again in a moment.' });
  }
});

app.patch('/api/admin/event', async (req, res) => {
  const { title, fellowship, description, guidance, cutoffDate, exchangeDate } = req.body;
  if (!title || !fellowship || !cutoffDate || !exchangeDate) return res.status(400).json({ error: 'Please fill in the event title, fellowship name, registration cutoff and Love Feast date.' });
  // The organizer form sends wall-clock Lagos time (datetime-local has no offset).
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(cutoffDate) || !/^\d{4}-\d{2}-\d{2}$/.test(exchangeDate)) return res.status(400).json({ error: 'Enter a valid cutoff time and Love Feast date.' });
  if (cutoffDate.slice(0, 10) > exchangeDate) return res.status(400).json({ error: 'The registration cutoff must be on or before the Love Feast date.' });
  try {
    const [event] = await sql`UPDATE exchanges SET title = ${title.trim()}, fellowship = ${fellowship.trim()}, description = ${String(description || '').trim()}, guidance = ${String(guidance || '').trim()}, cutoff_at = (${cutoffDate}::timestamp AT TIME ZONE ${eventTimeZone}), exchange_at = ${exchangeDate}, updated_at = now() WHERE id = ${exchangeId} RETURNING ${eventColumns}`;
    await audit('event_updated');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'We couldn’t save the event details. Please try again in a moment.' });
  }
});

app.post('/api/admin/roster', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const name = String(req.body.name || 'Unnamed member').trim();
  if (!/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid Nigerian mobile number, for example 0803 000 0001.' });
  try {
    const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id, normalized_phone, display_name`;
    if (!member) return res.status(409).json({ error: 'That number is already on the roster.' });
    await audit('roster_member_added');
    res.status(201).json(member);
  } catch {
    res.status(500).json({ error: 'We couldn’t add that member. Please try again in a moment.' });
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
        invalid.push({ phone: String(row.phone || '').trim(), reason: 'Not a valid Nigerian mobile number' });
        continue;
      }
      const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id`;
      if (member) added += 1;
    }
    await audit('roster_imported', { added, invalid: invalid.length });
    res.json({ added, invalid });
  } catch {
    res.status(500).json({ error: 'We couldn’t finish the import. Members added before the problem were saved; run the import again to add the rest.' });
  }
});

app.delete('/api/admin/roster/:id', async (req, res) => {
  try {
    const [member] = await sql`DELETE FROM eligible_members WHERE id = ${req.params.id} AND exchange_id = ${exchangeId} AND NOT EXISTS (SELECT 1 FROM participants WHERE eligible_member_id = eligible_members.id) RETURNING id`;
    if (!member) {
      const [existing] = await sql`SELECT display_name FROM eligible_members WHERE id = ${req.params.id} AND exchange_id = ${exchangeId}`;
      if (!existing) return res.status(404).json({ error: 'That member is no longer on the roster. Refresh the page to see the latest list.' });
      return res.status(409).json({ error: `${existing.display_name} has already registered. Remove them from the participant list first.` });
    }
    await audit('roster_member_removed');
    res.status(204).end();
  } catch {
    res.status(500).json({ error: 'We couldn’t remove that member. Please try again in a moment.' });
  }
});

app.post('/api/admin/close', async (_req, res) => {
  try {
    const [event] = await sql`UPDATE exchanges SET is_open = false, is_closed = true, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`;
    if (!event) return res.status(409).json({ error: 'The draw has already been run, so registration can’t be changed.' });
    await audit('registration_closed');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'We couldn’t close registration. Please try again in a moment.' });
  }
});

app.post('/api/admin/reopen', async (_req, res) => {
  try {
    const [event] = await sql`UPDATE exchanges SET is_open = true, is_closed = false, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`;
    if (!event) return res.status(409).json({ error: 'The draw has already been run, so registration can’t be reopened.' });
    await audit('registration_reopened');
    res.json(event);
  } catch {
    res.status(500).json({ error: 'We couldn’t reopen registration. Please try again in a moment.' });
  }
});

app.post('/api/register', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const name = String(req.body.name || '').trim().slice(0, 120);
  const giftHint = String(req.body.giftHint || '').trim().slice(0, 280);
  if (!name) return res.status(400).json({ error: 'Please enter your name.' });
  if (!/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid Nigerian WhatsApp number, for example 0803 000 0001.' });
  if (!req.body.commitmentAccepted) return res.status(400).json({ error: 'Please tick the gift promise to confirm you’ll take part.' });
  try {
    const [participant] = await sql`INSERT INTO participants (id, exchange_id, eligible_member_id, display_name, normalized_phone, gift_hint, status, commitment_accepted_at)
      SELECT ${crypto.randomUUID()}, e.id, m.id, ${name}, ${phone}, ${giftHint}, CASE WHEN m.id IS NULL THEN 'pending' ELSE 'approved' END, now()
      FROM exchanges e LEFT JOIN eligible_members m ON m.exchange_id = e.id AND m.normalized_phone = ${phone}
      WHERE e.id = ${exchangeId} AND e.is_open = true AND e.is_closed = false AND now() < e.cutoff_at
      ON CONFLICT (exchange_id, normalized_phone) DO NOTHING
      RETURNING id, display_name, status, registered_at`;
    if (!participant) {
      const [event] = await sql`SELECT is_open AND NOT is_closed AND now() < cutoff_at AS accepting FROM exchanges WHERE id = ${exchangeId}`;
      if (!event?.accepting) return res.status(409).json({ error: 'Registration for this exchange has closed. Please contact the organizer.' });
      return res.status(409).json({ error: 'This number is already registered. If that wasn’t you, please contact the organizer.' });
    }
    await audit('participant_registered', { status: participant.status });
    res.status(201).json({ participant });
  } catch {
    res.status(500).json({ error: 'We couldn’t save your registration. Please try again in a moment.' });
  }
});

app.post('/api/admin/participants/approve-all', async (_req, res) => {
  try {
    const approved = await sql`UPDATE participants SET status = 'approved' WHERE exchange_id = ${exchangeId} AND status = 'pending' AND NOT EXISTS (SELECT 1 FROM exchanges WHERE id = ${exchangeId} AND is_drawn) RETURNING id`;
    if (approved.length) await audit('participants_approved', { count: approved.length });
    res.json({ approved: approved.length });
  } catch {
    res.status(500).json({ error: 'We couldn’t approve those registrations. Please try again in a moment.' });
  }
});

app.post('/api/admin/participants/:id/approve', async (req, res) => {
  try {
    const [participant] = await sql`UPDATE participants SET status = 'approved' WHERE id = ${req.params.id} AND exchange_id = ${exchangeId} AND status = 'pending' RETURNING display_name`;
    if (!participant) return res.status(404).json({ error: 'That registration is no longer waiting for approval. Refresh the page to see the latest list.' });
    await audit('participant_approved', { participantId: req.params.id });
    res.json({ approved: participant.display_name });
  } catch {
    res.status(500).json({ error: 'We couldn’t approve that registration. Please try again in a moment.' });
  }
});

app.delete('/api/admin/participants/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const eventResult = await client.query('SELECT is_drawn FROM exchanges WHERE id = $1 FOR UPDATE', [exchangeId]);
    const participantResult = await client.query('SELECT id FROM participants WHERE id = $1 AND exchange_id = $2', [req.params.id, exchangeId]);
    if (!eventResult.rows[0] || !participantResult.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'That participant couldn’t be found. They may already have been removed; refresh the page.' });
    }
    if (!eventResult.rows[0].is_drawn) {
      await client.query('DELETE FROM participants WHERE id = $1', [req.params.id]);
      await auditWithClient(client, 'participant_removed', { drawn: false });
      await client.query('COMMIT');
      return res.json({ removed: true, affectedParticipant: null });
    }

    // The draw is a single gift ring, so the removed person's giver takes over their recipient.
    // Only that one giver's match changes; everyone else keeps theirs.
    const countResult = await client.query('SELECT count(*)::int AS count FROM participants WHERE exchange_id = $1', [exchangeId]);
    if (countResult.rows[0].count <= 2) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'At least two participants must remain after a removal.' });
    }
    const ringResult = await client.query(`SELECT incoming.giver_participant_id AS giver_id, outgoing.recipient_participant_id AS recipient_id, giver.display_name AS giver_name
      FROM assignments incoming
      JOIN assignments outgoing ON outgoing.giver_participant_id = incoming.recipient_participant_id AND outgoing.exchange_id = incoming.exchange_id
      JOIN participants giver ON giver.id = incoming.giver_participant_id
      WHERE incoming.recipient_participant_id = $1 AND incoming.exchange_id = $2`, [req.params.id, exchangeId]);
    const ring = ringResult.rows[0];
    if (!ring) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'That participant’s gift match couldn’t be found, so nothing was changed. Refresh the page and try again.' });
    }
    await client.query('DELETE FROM participants WHERE id = $1', [req.params.id]);
    await client.query('INSERT INTO assignments (id, exchange_id, giver_participant_id, recipient_participant_id) VALUES ($1, $2, $3, $4)', [crypto.randomUUID(), exchangeId, ring.giver_id, ring.recipient_id]);
    // Their existing link now shows the new match; clear "opened" so the organizer can see when they've checked again.
    await client.query('UPDATE reveal_tokens SET viewed_at = NULL WHERE participant_id = $1 AND revoked_at IS NULL', [ring.giver_id]);
    await auditWithClient(client, 'participant_removed', { drawn: true, reassignedGiverId: ring.giver_id });
    await client.query('COMMIT');
    res.json({ removed: true, affectedParticipant: ring.giver_name });
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'We couldn’t remove that participant, so nothing was changed. Please try again in a moment.' });
  } finally {
    client.release();
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
      return res.status(409).json({ error: event?.is_drawn ? 'The draw has already been run. It can only happen once.' : 'Close registration before running the draw.' });
    }
    const participantResult = await client.query('SELECT id, display_name, status FROM participants WHERE exchange_id = $1 ORDER BY registered_at FOR UPDATE', [exchangeId]);
    const pending = participantResult.rows.filter(row => row.status !== 'approved').length;
    if (pending) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `${pending} ${pending === 1 ? 'person is' : 'people are'} still waiting for approval. Approve or decline them before running the draw.` });
    }
    if (participantResult.rows.length < 2) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'At least two approved participants are needed before you can run the draw.' });
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
    res.status(500).json({ error: 'The draw didn’t finish, so no assignments were saved. Please try again in a moment.' });
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
      return res.status(404).json({ error: 'That participant doesn’t have a gift match yet. Refresh the page and try again.' });
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
    res.status(500).json({ error: 'We couldn’t replace that private link. Please try again in a moment.' });
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
      return res.status(404).json({ error: 'That participant has no active link to revoke. Refresh the page to see the latest status.' });
    }
    await auditWithClient(client, 'reveal_link_revoked', { participantId: req.params.participantId });
    await client.query('COMMIT');
    res.status(204).end();
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'We couldn’t revoke that private link. Please try again in a moment.' });
  } finally {
    client.release();
  }
});

app.post('/api/reveal', sameOriginOnly, async (req, res) => {
  const rawToken = String(req.body.token || '');
  const invalidLink = 'This link isn’t valid. Make sure you opened the full link from your WhatsApp message, or ask the organizer to resend it.';
  if (!rawToken || rawToken.length > 100) return res.status(404).json({ error: invalidLink });
  try {
    const tokenHash = hashToken(rawToken);
    const [link] = await sql`SELECT revoked_at IS NOT NULL AS revoked, expires_at IS NOT NULL AND expires_at <= now() AS expired FROM reveal_tokens WHERE token_hash = ${tokenHash}`;
    if (!link) return res.status(404).json({ error: invalidLink });
    if (link.revoked) return res.status(410).json({ error: 'This link was replaced or turned off by the organizer. Ask them to send you your current link.' });
    if (link.expired) return res.status(410).json({ error: 'This link has expired because the Love Feast is over.' });
    const [result] = await sql`SELECT p.display_name AS participant_name, recipient.display_name AS recipient_name, recipient.gift_hint AS recipient_hint, e.guidance
      FROM reveal_tokens t
      JOIN participants p ON p.id = t.participant_id
      JOIN assignments a ON a.giver_participant_id = p.id
      JOIN participants recipient ON recipient.id = a.recipient_participant_id
      JOIN exchanges e ON e.id = t.exchange_id
      WHERE t.token_hash = ${tokenHash} AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())`;
    if (!result) return res.status(404).json({ error: 'We couldn’t find a gift match for this link. Please contact the organizer.' });
    const organizerPreview = Boolean(await findOrganizerSession(req));
    if (!organizerPreview) await sql`UPDATE reveal_tokens SET viewed_at = COALESCE(viewed_at, now()) WHERE token_hash = ${tokenHash}`;
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ...result, organizerPreview });
  } catch {
    res.status(500).json({ error: 'We couldn’t load your match. Please try again in a moment.' });
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

app.use('/api', (_req, res) => res.status(404).json({ error: 'That page or action doesn’t exist.' }));
// Anything uncaught (bad JSON, an oversized body, a lost database connection) still answers in plain words.
app.use((error, _req, res, _next) => {
  if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'The request couldn’t be read. Please refresh the page and try again.' });
  if (error.type === 'entity.too.large') return res.status(413).json({ error: 'That’s too much text to send at once. Try importing the roster in smaller batches.' });
  console.error(error);
  res.status(500).json({ error: 'Something went wrong on our side. Please try again in a moment.' });
});
app.use((_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

if (!process.env.VERCEL) app.listen(port, () => console.log(`Love Feast running at http://localhost:${port}`));

export default app;

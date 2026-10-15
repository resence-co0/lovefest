import dotenv from 'dotenv';
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || '.env.local' });
import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { neon } from '@neondatabase/serverless';
import { S3Client, HeadBucketCommand } from '@aws-sdk/client-s3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const sql = neon(process.env.DATABASE_URL);
const exchangeId = process.env.EXCHANGE_ID || '00000000-0000-4000-8000-000000000001';
const port = Number(process.env.PORT || 4173);

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

function normalizePhone(value) {
  let phone = String(value || '').replace(/[\s().-]/g, '');
  if (/^0[789]\d{9}$/.test(phone)) phone = '+234' + phone.slice(1);
  if (/^234[789]\d{9}$/.test(phone)) phone = '+' + phone;
  return phone;
}

function adminOnly(req, res, next) {
  const expected = process.env.ORGANIZER_KEY || 'demo-organizer-key';
  if (req.get('x-organizer-key') !== expected) return res.status(401).json({ error: 'Organizer access required.' });
  next();
}

async function audit(action, metadata = {}) {
  await sql`INSERT INTO audit_events (id, exchange_id, action, metadata) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${action}, ${JSON.stringify(metadata)})`;
}

app.get('/api/event', async (_req, res) => {
  try {
    const [event] = await sql`SELECT id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn FROM exchanges WHERE id = ${exchangeId}`;
    if (!event) return res.status(404).json({ error: 'Event not found.' });
    res.json(event);
  } catch (error) { res.status(500).json({ error: 'Unable to load the event.' }); }
});

app.get('/api/admin/state', adminOnly, async (_req, res) => {
  try {
    const [event] = await sql`SELECT id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn FROM exchanges WHERE id = ${exchangeId}`;
    const roster = await sql`SELECT id, normalized_phone, display_name, EXISTS (SELECT 1 FROM participants p WHERE p.eligible_member_id = eligible_members.id) AS registered FROM eligible_members WHERE exchange_id = ${exchangeId} ORDER BY display_name`;
    const participants = await sql`SELECT id, display_name, normalized_phone, commitment_accepted_at, registered_at FROM participants WHERE exchange_id = ${exchangeId} ORDER BY registered_at`;
    res.json({ event, roster, participants });
  } catch (error) { res.status(500).json({ error: 'Unable to load organizer state.' }); }
});

app.patch('/api/admin/event', adminOnly, async (req, res) => {
  const { title, fellowship, description, guidance, cutoffDate, exchangeDate } = req.body;
  if (!title || !fellowship || !cutoffDate || !exchangeDate) return res.status(400).json({ error: 'Title, fellowship, cutoff and exchange date are required.' });
  try {
    const [event] = await sql`UPDATE exchanges SET title = ${title.trim()}, fellowship = ${fellowship.trim()}, description = ${String(description || '').trim()}, guidance = ${String(guidance || '').trim()}, cutoff_at = ${cutoffDate}, exchange_at = ${exchangeDate}, updated_at = now() WHERE id = ${exchangeId} RETURNING id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn`;
    await audit('event_updated');
    res.json(event);
  } catch (error) { res.status(500).json({ error: 'Unable to update event.' }); }
});

app.post('/api/admin/roster', adminOnly, async (req, res) => {
  const phone = normalizePhone(req.body.phone); const name = String(req.body.name || 'Unnamed member').trim();
  if (!/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid Nigerian phone number.' });
  try {
    const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id, normalized_phone, display_name`;
    if (!member) return res.status(409).json({ error: 'That number is already on the roster.' });
    await audit('roster_member_added'); res.status(201).json(member);
  } catch (error) { res.status(500).json({ error: 'Unable to add roster member.' }); }
});

app.post('/api/admin/roster/import', adminOnly, async (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  let added = 0; const invalid = [];
  for (const row of rows) {
    const phone = normalizePhone(row.phone); const name = String(row.name || 'Unnamed member').trim();
    if (!/^\+234[789]\d{9}$/.test(phone)) { invalid.push({ phone: row.phone, reason: 'Invalid Nigerian number' }); continue; }
    const [member] = await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name}) ON CONFLICT (exchange_id, normalized_phone) DO NOTHING RETURNING id`;
    if (member) added += 1;
  }
  await audit('roster_imported', { added, invalid: invalid.length }); res.json({ added, invalid });
});

app.delete('/api/admin/roster/:id', adminOnly, async (req, res) => {
  try {
    const [member] = await sql`DELETE FROM eligible_members WHERE id = ${req.params.id} AND exchange_id = ${exchangeId} AND NOT EXISTS (SELECT 1 FROM participants WHERE eligible_member_id = eligible_members.id) RETURNING id`;
    if (!member) return res.status(409).json({ error: 'That member is registered or cannot be removed.' });
    await audit('roster_member_removed'); res.status(204).end();
  } catch (error) { res.status(500).json({ error: 'Unable to remove roster member.' }); }
});

app.post('/api/admin/close', adminOnly, async (_req, res) => {
  try { const [event] = await sql`UPDATE exchanges SET is_open = false, is_closed = true, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`; await audit('registration_closed'); res.json(event); } catch (error) { res.status(500).json({ error: 'Unable to close registration.' }); }
});

app.post('/api/admin/reopen', adminOnly, async (_req, res) => {
  try { const [event] = await sql`UPDATE exchanges SET is_open = true, is_closed = false, updated_at = now() WHERE id = ${exchangeId} AND is_drawn = false RETURNING is_open, is_closed`; await audit('registration_reopened'); res.json(event); } catch (error) { res.status(500).json({ error: 'Unable to reopen registration.' }); }
});

app.post('/api/register', async (req, res) => {
  const phone = normalizePhone(req.body.phone); const name = String(req.body.name || '').trim();
  if (!name || !req.body.commitmentAccepted || !/^\+234[789]\d{9}$/.test(phone)) return res.status(400).json({ error: 'We couldn’t complete that registration. Please check your details or contact the organizer.' });
  try {
    const [participant] = await sql`INSERT INTO participants (id, exchange_id, eligible_member_id, display_name, normalized_phone, commitment_accepted_at)
      SELECT ${crypto.randomUUID()}, e.id, m.id, ${name}, m.normalized_phone, now() FROM exchanges e JOIN eligible_members m ON m.exchange_id = e.id AND m.normalized_phone = ${phone}
      WHERE e.id = ${exchangeId} AND e.is_open = true AND e.is_closed = false AND now() < e.cutoff_at
      AND NOT EXISTS (SELECT 1 FROM participants p WHERE p.exchange_id = e.id AND p.normalized_phone = m.normalized_phone)
      RETURNING id, display_name, registered_at`;
    if (!participant) return res.status(400).json({ error: 'We couldn’t complete that registration. Please check your details or contact the organizer.' });
    await audit('participant_registered'); res.status(201).json({ participant });
  } catch (error) { res.status(500).json({ error: 'Unable to complete registration.' }); }
});

app.post('/api/admin/draw', adminOnly, async (_req, res) => {
  try {
    const [event] = await sql`SELECT is_closed, is_drawn FROM exchanges WHERE id = ${exchangeId}`;
    if (!event?.is_closed || event.is_drawn) return res.status(409).json({ error: 'Registration must be closed and the draw must not already exist.' });
    const participants = await sql`SELECT id, display_name FROM participants WHERE exchange_id = ${exchangeId} ORDER BY registered_at`;
    if (participants.length < 2) return res.status(400).json({ error: 'At least two participants are required.' });
    let shuffled = [...participants];
    for (let index = shuffled.length - 1; index > 0; index -= 1) { const random = crypto.randomInt(index + 1); [shuffled[index], shuffled[random]] = [shuffled[random], shuffled[index]]; }
    if (shuffled.some((participant, index) => participant.id === shuffled[(index + 1) % shuffled.length].id)) return res.status(409).json({ error: 'Please retry the draw.' });
    const links = [];
    for (let index = 0; index < shuffled.length; index += 1) {
      const giver = shuffled[index]; const recipient = shuffled[(index + 1) % shuffled.length]; const rawToken = crypto.randomBytes(32).toString('base64url'); const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      await sql`INSERT INTO assignments (id, exchange_id, giver_participant_id, recipient_participant_id) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${giver.id}, ${recipient.id})`;
      await sql`INSERT INTO reveal_tokens (id, exchange_id, participant_id, token_hash) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${giver.id}, ${tokenHash})`;
      links.push({ participantId: giver.id, participantName: giver.display_name, token: rawToken });
    }
    await sql`UPDATE exchanges SET is_drawn = true, updated_at = now() WHERE id = ${exchangeId}`; await audit('draw_completed'); res.json({ links });
  } catch (error) { res.status(500).json({ error: 'Unable to complete the draw.' }); }
});

app.get('/api/reveal/:token', async (req, res) => {
  const hash = crypto.createHash('sha256').update(req.params.token).digest('hex');
  try {
    const [result] = await sql`SELECT p.display_name AS participant_name, recipient.display_name AS recipient_name, e.guidance FROM reveal_tokens t JOIN participants p ON p.id = t.participant_id JOIN assignments a ON a.giver_participant_id = p.id JOIN participants recipient ON recipient.id = a.recipient_participant_id JOIN exchanges e ON e.id = t.exchange_id WHERE t.token_hash = ${hash} AND t.revoked_at IS NULL`;
    if (!result) return res.status(404).json({ error: 'This private reveal link is invalid or has expired.' });
    await sql`UPDATE reveal_tokens SET viewed_at = COALESCE(viewed_at, now()) WHERE token_hash = ${hash}`; res.json(result);
  } catch (error) { res.status(500).json({ error: 'Unable to load this reveal.' }); }
});

app.get('/api/storage/health', async (_req, res) => {
  if (!process.env.AWS_ENDPOINT_URL_S3 || !process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) return res.status(503).json({ configured: false });
  try { const client = new S3Client({ endpoint: process.env.AWS_ENDPOINT_URL_S3, region: process.env.AWS_REGION || 'eu-central-1', forcePathStyle: true }); await client.send(new HeadBucketCommand({ Bucket: process.env.S3_BUCKET || 'assets' })); res.json({ configured: true, bucket: process.env.S3_BUCKET || 'assets' }); } catch (error) { res.status(502).json({ configured: true, reachable: false, error: 'Storage service could not be reached.' }); }
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (!process.env.VERCEL) app.listen(port, () => console.log(`Love Feast running at http://localhost:${port}`));

export default app;

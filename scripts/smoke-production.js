import dotenv from 'dotenv';
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || '.env.local' });

import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import pg from 'pg';

const exchangeId = crypto.randomUUID();
const port = 4187;
const origin = `http://localhost:${port}`;
const organizerPassword = `test-${crypto.randomBytes(16).toString('hex')}`;
const sessionSecret = crypto.randomBytes(32).toString('hex');
const linkSecret = crypto.randomBytes(32).toString('hex');
const pgConnectionString = String(process.env.DATABASE_URL || '').replace('sslmode=require', 'sslmode=verify-full');
const pool = new pg.Pool({ connectionString: pgConnectionString, max: 1 });
let server;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function json(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(`${response.status}: ${body.error || 'Request failed'}`);
  return body;
}

async function waitForServer(child) {
  await new Promise((resolve, reject) => {
    let stderr = '';
    const timeout = setTimeout(() => reject(new Error(`Server startup timed out. ${stderr}`)), 10_000);
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.stdout.on('data', chunk => {
      if (chunk.toString().includes('Love Feast running')) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.once('exit', code => {
      clearTimeout(timeout);
      reject(new Error(`Server exited during startup with code ${code}. ${stderr}`));
    });
  });
}

async function adminFetch(path, cookie, options = {}) {
  return fetch(`${origin}/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: cookie, ...(options.headers || {}) }
  });
}

try {
  await pool.query(`INSERT INTO exchanges (id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn)
    VALUES ($1, 'Integration Test Exchange', 'Test Fellowship', 'Temporary automated test', 'Test gift', '2099-01-01T00:00:00+01:00', '2099-01-02', true, false, false)`, [exchangeId]);

  for (let index = 0; index < 5; index += 1) {
    const memberId = crypto.randomUUID();
    const participantId = crypto.randomUUID();
    const phone = `+234803999990${index}`;
    await pool.query('INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES ($1, $2, $3, $4)', [memberId, exchangeId, phone, `Test Member ${index + 1}`]);
    await pool.query(`INSERT INTO participants (id, exchange_id, eligible_member_id, display_name, normalized_phone, commitment_accepted_at)
      VALUES ($1, $2, $3, $4, $5, now())`, [participantId, exchangeId, memberId, `Test Member ${index + 1}`, phone]);
    await pool.query('UPDATE participants SET gift_hint = $1 WHERE id = $2', [`Hint from Test Member ${index + 1}`, participantId]);
  }

  server = spawn(process.execPath, ['server.js'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, EXCHANGE_ID: exchangeId, PORT: String(port), ORGANIZER_PASSWORD: organizerPassword, SESSION_SECRET: sessionSecret, LINK_ENCRYPTION_SECRET: linkSecret },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitForServer(server);

  const denied = await fetch(`${origin}/api/admin/state`);
  assert(denied.status === 401, 'Unauthenticated organizer access was not denied.');

  const login = await adminFetch('/admin/login', '', { method: 'POST', body: JSON.stringify({ password: organizerPassword }) });
  assert(login.status === 200, 'Organizer login failed.');
  const cookie = String(login.headers.get('set-cookie')).split(';')[0];
  assert(cookie.startsWith('lovefeast_admin='), 'Organizer session cookie was not issued.');

  const beforeDraw = await json(await adminFetch('/admin/state', cookie));
  const dropout = beforeDraw.participants[0];
  await json(await adminFetch(`/admin/participants/${dropout.id}`, cookie, { method: 'DELETE' }));
  const afterDropout = await json(await adminFetch('/admin/state', cookie));
  assert(afterDropout.participants.length === 4 && afterDropout.roster.length === 5, 'Removing a participant before the draw should keep them on the roster.');

  const newcomer = await json(await fetch(`${origin}/api/register`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ name: 'Walk-in Member', phone: '0803 999 9999', giftHint: 'Hint from Walk-in Member', commitmentAccepted: true }) }));
  assert(newcomer.participant.status === 'pending', 'A number that is not pre-approved was not left pending.');
  const duplicate = await fetch(`${origin}/api/register`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ name: 'Walk-in Again', phone: '08039999999', commitmentAccepted: true }) });
  assert(duplicate.status === 409, 'The same number was allowed to register twice.');

  await json(await adminFetch('/admin/close', cookie, { method: 'POST' }));
  const blockedDraw = await adminFetch('/admin/draw', cookie, { method: 'POST' });
  assert(blockedDraw.status === 409, 'The draw ran while a registration was still waiting for approval.');
  await json(await adminFetch(`/admin/participants/${newcomer.participant.id}/approve`, cookie, { method: 'POST' }));
  const closedRegistration = await fetch(`${origin}/api/register`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ name: 'Late Member', phone: dropout.normalized_phone, commitmentAccepted: true }) });
  assert(closedRegistration.status === 409, 'Registration after closing did not report that registration has closed.');

  const draw = await json(await adminFetch('/admin/draw', cookie, { method: 'POST' }));
  assert(draw.links.length === 5, 'Draw did not create one link per participant.');
  assert(new Set(draw.links.map(link => link.token)).size === 5, 'Reveal tokens are not unique.');

  const refreshed = await json(await adminFetch('/admin/state', cookie));
  assert(refreshed.links.length === 5 && refreshed.links.every(link => link.token), 'Encrypted reveal links were not recoverable after refresh.');

  const preview = await json(await adminFetch('/reveal', cookie, { method: 'POST', body: JSON.stringify({ token: refreshed.links[1].token }) }));
  const afterPreview = await json(await adminFetch('/admin/state', cookie));
  assert(preview.organizerPreview === true && !afterPreview.links[1].viewedAt, 'An organizer preview was counted as the participant opening their link.');

  async function ring() {
    const { rows } = await pool.query('SELECT giver_participant_id AS giver, recipient_participant_id AS recipient FROM assignments WHERE exchange_id = $1', [exchangeId]);
    return new Map(rows.map(row => [row.giver, row.recipient]));
  }
  function isSingleCycle(pairs) {
    const visited = new Set();
    for (let step = 0, node = pairs.keys().next().value; step < pairs.size; step += 1, node = pairs.get(node)) visited.add(node);
    return visited.size === pairs.size && [...pairs].every(([giver, recipient]) => giver !== recipient);
  }
  const ringBefore = await ring();
  assert(isSingleCycle(ringBefore), 'The draw is not a single gift ring.');
  const leaving = refreshed.links[2].participantId;
  const giverOfLeaving = [...ringBefore].find(([, recipient]) => recipient === leaving)[0];
  const removal = await json(await adminFetch(`/admin/participants/${leaving}`, cookie, { method: 'DELETE' }));
  const ringAfter = await ring();
  assert(removal.affectedParticipant && ringAfter.size === 4 && isSingleCycle(ringAfter), 'Removing a participant after the draw did not leave a valid ring.');
  assert(ringAfter.get(giverOfLeaving) === ringBefore.get(leaving), 'The removed participant’s giver was not given their recipient.');
  assert([...ringAfter].filter(([giver, recipient]) => ringBefore.get(giver) !== recipient).length === 1, 'More than one assignment changed after a removal.');

  const remaining = (await json(await adminFetch('/admin/state', cookie))).participants;
  await json(await adminFetch(`/admin/participants/${remaining[0].id}`, cookie, { method: 'DELETE' }));
  await json(await adminFetch(`/admin/participants/${remaining[1].id}`, cookie, { method: 'DELETE' }));
  const tooFew = await adminFetch(`/admin/participants/${remaining[2].id}`, cookie, { method: 'DELETE' });
  assert(tooFew.status === 409, 'Removal was allowed even though it would leave fewer than two participants.');

  const first = refreshed.links.find(link => link.participantId === remaining[2].id);
  const firstReveal = await json(await fetch(`${origin}/api/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ token: first.token }) }));
  assert(firstReveal.participant_name !== firstReveal.recipient_name, 'A participant was assigned to themselves.');
  assert(firstReveal.recipient_hint === `Hint from ${firstReveal.recipient_name}`, 'The reveal did not include the recipient’s gift hint.');

  const replacement = await json(await adminFetch(`/admin/reveal/${first.participantId}/regenerate`, cookie, { method: 'POST' }));
  const oldLink = await fetch(`${origin}/api/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ token: first.token }) });
  assert(oldLink.status === 410, 'Replaced reveal link remained active.');
  await json(await fetch(`${origin}/api/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ token: replacement.token }) }));

  const revoked = await adminFetch(`/admin/reveal/${first.participantId}/revoke`, cookie, { method: 'POST' });
  assert(revoked.status === 204, 'Reveal link revocation failed.');
  const revokedLink = await fetch(`${origin}/api/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ token: replacement.token }) });
  assert(revokedLink.status === 410, 'Revoked reveal link remained active.');

  console.log(JSON.stringify({ authenticated: true, pendingApprovalEnforced: true, assignments: draw.links.length, removalBeforeDraw: true, closedRegistrationMessage: true, organizerPreviewNotCounted: true, removalAfterDrawRepairsRing: true, linksRecovered: true, replacementInvalidatedOldLink: true, revocationEnforced: true }));
} finally {
  if (server && !server.killed) server.kill('SIGTERM');
  await pool.query('DELETE FROM exchanges WHERE id = $1', [exchangeId]);
  await pool.end();
}

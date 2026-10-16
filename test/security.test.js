import test from 'node:test';
import assert from 'node:assert/strict';
import { createDraw } from '../lib/draw.js';
import { createOpaqueToken, decryptToken, encryptToken, hashToken, secretsMatch } from '../lib/security.js';

test('opaque tokens are random and hash consistently', () => {
  const first = createOpaqueToken();
  const second = createOpaqueToken();
  assert.notEqual(first, second);
  assert.equal(hashToken(first), hashToken(first));
  assert.notEqual(hashToken(first), first);
});

test('encrypted reveal tokens can be recovered only with the correct secret', () => {
  const secret = 'a-production-length-secret-value-123456';
  const token = createOpaqueToken();
  const encrypted = encryptToken(token, secret);
  assert.notEqual(encrypted, token);
  assert.equal(decryptToken(encrypted, secret), token);
  assert.throws(() => decryptToken(encrypted, 'a-different-production-secret-12345'));
});

test('organizer secret comparison is timing safe and rejects missing values', () => {
  assert.equal(secretsMatch('correct horse', 'correct horse'), true);
  assert.equal(secretsMatch('wrong horse', 'correct horse'), false);
  assert.equal(secretsMatch('', 'correct horse'), false);
});

test('draw gives every participant exactly one different recipient', () => {
  const participants = Array.from({ length: 12 }, (_, index) => ({ id: `person-${index}` }));
  const assignments = createDraw(participants);
  assert.equal(assignments.length, participants.length);
  assert.equal(new Set(assignments.map(item => item.giver.id)).size, participants.length);
  assert.equal(new Set(assignments.map(item => item.recipient.id)).size, participants.length);
  assert.equal(assignments.some(item => item.giver.id === item.recipient.id), false);
});

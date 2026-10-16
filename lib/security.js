import crypto from 'node:crypto';

export function hashToken(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

export function secretsMatch(candidate, expected) {
  if (!candidate || !expected) return false;
  const candidateHash = crypto.createHash('sha256').update(String(candidate)).digest();
  const expectedHash = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(candidateHash, expectedHash);
}

export function createOpaqueToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function encryptionKey(secret) {
  if (!secret || secret.length < 32) throw new Error('LINK_ENCRYPTION_SECRET must be at least 32 characters.');
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptToken(token, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(secret), iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64url'), tag.toString('base64url'), encrypted.toString('base64url')].join('.');
}

export function decryptToken(payload, secret) {
  const [version, ivValue, tagValue, encryptedValue] = String(payload || '').split('.');
  if (version !== 'v1' || !ivValue || !tagValue || !encryptedValue) throw new Error('Invalid encrypted token.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(secret), Buffer.from(ivValue, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagValue, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(encryptedValue, 'base64url')), decipher.final()]).toString('utf8');
}

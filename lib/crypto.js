const crypto = require('crypto');
const { promisify } = require('util');
const pbkdf2 = promisify(crypto.pbkdf2);

const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

async function deriveKey(password, salt) {
  return pbkdf2(password, salt, 200000, KEY_BYTES, 'sha256');
}
function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
async function encryptBlock(plain, key, index) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(index)));
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}
async function decryptBlock(payload, key, index) {
  if (payload.length < IV_BYTES + TAG_BYTES) throw new Error('Encrypted block is incomplete.');
  const iv = payload.subarray(0, IV_BYTES);
  const tag = payload.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const encrypted = payload.subarray(IV_BYTES + TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(String(index)));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
module.exports = { deriveKey, sha256, encryptBlock, decryptBlock, SALT_BYTES };

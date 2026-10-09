const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { deriveKey, sha256, encryptBlock, decryptBlock, SALT_BYTES } = require('./lib/crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const CLOUD_DIR = path.join(__dirname, 'cloud');
const TMP_DIR = path.join(__dirname, 'tmp');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const scrypt = promisify(crypto.scrypt);
fs.mkdirSync(CLOUD_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({ dest: TMP_DIR, limits: { fileSize: 200 * 1024 * 1024 } });
const BLOCK_SIZES = { '64kb': 64 * 1024, '256kb': 256 * 1024, '1mb': 1024 * 1024, '4mb': 4 * 1024 * 1024 };
const sessions = new Map();
const safeId = id => /^[a-f0-9-]{20,40}$/i.test(String(id));
const manifestPath = id => path.join(CLOUD_DIR, id, 'manifest.json');
const cleanName = name => path.basename(name || 'download').replace(/[\x00-\x1f]/g, '').slice(0, 180) || 'download';
const emailNorm = email => String(email || '').trim().toLowerCase();
async function readUsers() { return JSON.parse(await fsp.readFile(USERS_FILE, 'utf8')); }
async function writeUsers(users) { await fsp.writeFile(USERS_FILE, JSON.stringify(users, null, 2)); }
async function readManifest(id) {
  if (!safeId(id)) { const e = new Error('Invalid file identifier.'); e.status = 400; throw e; }
  try { return JSON.parse(await fsp.readFile(manifestPath(id), 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') { const x = new Error('File not found.'); x.status = 404; throw x; } throw e; }
}
function getToken(req) { return (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('bv_session='))?.slice('bv_session='.length); }
function requireAuth(req, res, next) {
  const token = getToken(req); const user = token && sessions.get(token);
  if (!user) return res.status(401).json({ error: 'Please sign in to continue.' });
  req.user = user; next();
}
function setSession(res, user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { id: user.id, name: user.name, email: user.email });
  res.setHeader('Set-Cookie', `bv_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`);
}
app.get('/api/health', (_req, res) => res.json({ ok: true, storage: 'local-simulated-cloud' }));
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 80);
    const email = emailNorm(req.body.email);
    const password = String(req.body.password || '');
    if (name.length < 2) return res.status(400).json({ error: 'Enter your full name (at least 2 characters).' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8) return res.status(400).json({ error: 'Account password must be at least 8 characters.' });
    const users = await readUsers();
    if (users.some(u => u.email === email)) return res.status(409).json({ error: 'An account with this email already exists. Sign in instead.' });
    const salt = crypto.randomBytes(16); const hash = await scrypt(password, salt, 64);
    const user = { id: crypto.randomUUID(), name, email, salt: salt.toString('hex'), passwordHash: hash.toString('hex'), createdAt: new Date().toISOString() };
    users.push(user); await writeUsers(users); setSession(res, user);
    res.status(201).json({ user: { id: user.id, name, email }, message: 'Your secure account is ready.' });
  } catch (e) { next(e); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = emailNorm(req.body.email); const password = String(req.body.password || '');
    const users = await readUsers(); const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const candidate = await scrypt(password, Buffer.from(user.salt, 'hex'), 64);
    if (!crypto.timingSafeEqual(candidate, Buffer.from(user.passwordHash, 'hex'))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    setSession(res, user); res.json({ user: { id: user.id, name: user.name, email: user.email }, message: 'Welcome back.' });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', (req, res) => {
  const token = getToken(req); if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'bv_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); res.json({ message: 'You have signed out.' });
});
app.get('/api/files', requireAuth, async (req, res, next) => {
  try {
    const dirs = await fsp.readdir(CLOUD_DIR, { withFileTypes: true }); const files = [];
    for (const d of dirs) if (d.isDirectory()) {
      try { const m = await readManifest(d.name); if (m.userId === req.user.id) files.push({ id: m.id, name: m.originalName, size: m.originalSize, blocks: m.blocks.length, blockSize: m.blockSize, uploadedAt: m.uploadedAt, hash: m.originalSha256, mimeType: m.mimeType || 'application/octet-stream' }); } catch (_) {}
    }
    files.sort((a,b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    res.json({ files, usedBytes: files.reduce((sum, f) => sum + f.size, 0), maxBytes: 200 * 1024 * 1024 });
  } catch (e) { next(e); }
});
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res, next) => {
  const tempPath = req.file?.path; let dir;
  try {
    if (!req.file) return res.status(400).json({ error: 'Choose a file to upload.' });
    const password = String(req.body.password || '');
    if (password.length < 6) return res.status(400).json({ error: 'Encryption password must contain at least 6 characters.' });
    const blockSize = BLOCK_SIZES[String(req.body.blockSize || '1mb').toLowerCase()];
    if (!blockSize) return res.status(400).json({ error: 'Choose a supported block size.' });
    const id = crypto.randomUUID(); dir = path.join(CLOUD_DIR, id); await fsp.mkdir(dir, { recursive: true });
    const salt = crypto.randomBytes(SALT_BYTES); const key = await deriveKey(password, salt); const data = await fsp.readFile(tempPath); const blocks = [];
    for (let offset = 0, index = 0; offset < data.length || (data.length === 0 && index === 0); offset += blockSize, index++) {
      const plain = data.subarray(offset, Math.min(offset + blockSize, data.length)); const encrypted = await encryptBlock(plain, key, index);
      const filename = `block_${String(index).padStart(5, '0')}.bin`; await fsp.writeFile(path.join(dir, filename), encrypted);
      blocks.push({ index, filename, plainSize: plain.length, storedSize: encrypted.length, sha256: sha256(encrypted) }); if (data.length === 0) break;
    }
    const manifest = { version: 1, id, userId: req.user.id, originalName: cleanName(req.file.originalname), mimeType: req.file.mimetype || 'application/octet-stream', originalSize: data.length, originalSha256: sha256(data), blockSize, salt: salt.toString('base64'), kdf: 'PBKDF2-SHA256-200000', cipher: 'AES-256-GCM', uploadedAt: new Date().toISOString(), blocks };
    await fsp.writeFile(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
    res.status(201).json({ message: 'File encrypted and segmented successfully.', file: { id, name: manifest.originalName, size: manifest.originalSize, blocks: blocks.length, blockSize, uploadedAt: manifest.uploadedAt } });
  } catch (e) { if (dir) await fsp.rm(dir, { recursive: true, force: true }).catch(()=>{}); next(e); }
  finally { if (tempPath) await fsp.rm(tempPath, { force: true }).catch(()=>{}); }
});
async function ownedManifest(req) { const m = await readManifest(req.params.id); if (m.userId !== req.user.id) { const e = new Error('File not found in your account.'); e.status = 404; throw e; } return m; }
app.get('/api/files/:id/encrypted', requireAuth, async (req, res, next) => {
  try {
    const m = await ownedManifest(req); const bundle = { format: 'BLOCKVAULT-ENC-1', manifest: m, blocks: [] };
    for (const b of m.blocks) { const buf = await fsp.readFile(path.join(CLOUD_DIR, m.id, b.filename)); if (sha256(buf) !== b.sha256) return res.status(409).json({ error: `Integrity check failed for block ${b.index}.` }); bundle.blocks.push(buf.toString('base64')); }
    res.setHeader('Content-Type', 'application/octet-stream'); res.setHeader('Content-Disposition', `attachment; filename="${cleanName(m.originalName)}.enc"`); res.send(Buffer.from(JSON.stringify(bundle)));
  } catch (e) { next(e); }
});
app.post('/api/files/:id/decrypt', requireAuth, async (req, res, next) => {
  try {
    const m = await ownedManifest(req); const password = String(req.body.password || ''); if (!password) return res.status(400).json({ error: 'Enter the encryption password.' });
    const key = await deriveKey(password, Buffer.from(m.salt, 'base64')); const output = [];
    for (const b of m.blocks) { const payload = await fsp.readFile(path.join(CLOUD_DIR, m.id, b.filename)); if (sha256(payload) !== b.sha256) return res.status(409).json({ error: `Integrity check failed for block ${b.index}. The stored data may have changed.` }); output.push(await decryptBlock(payload, key, b.index)); }
    const original = Buffer.concat(output); if (sha256(original) !== m.originalSha256) return res.status(409).json({ error: 'Original file hash mismatch. File integrity could not be verified.' });
    res.setHeader('Content-Type', m.mimeType || 'application/octet-stream'); res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(m.originalName)}`); res.setHeader('X-Content-Type-Options', 'nosniff'); res.send(original);
  } catch (e) { if (e.message && /authenticate|Unsupported state|unable to authenticate/i.test(e.message)) return res.status(400).json({ error: 'Wrong password or corrupted encrypted block. No file was produced.' }); next(e); }
});
app.delete('/api/files/:id', requireAuth, async (req, res, next) => {
  try { const m = await ownedManifest(req); await fsp.rm(path.join(CLOUD_DIR, m.id), { recursive: true, force: true }); res.json({ message: 'File and encrypted blocks deleted.' }); } catch (e) { next(e); }
});
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Maximum upload size is 200 MB.' });
  const status = err.status || 500; res.status(status).json({ error: status === 500 ? 'Something went wrong while processing the request.' : err.message });
});
app.listen(PORT, () => console.log(`BlockVault running at http://localhost:${PORT}`));

# BlockVault — Secure File Storage Website

A Cloud Computing mini-project implementation based on the report, with a redesigned professional UI, account registration/sign-in, per-user file vaults, file segmentation, authenticated encryption, encrypted download, restore, preview/open, search, refresh, and delete.

## Requirements
- Node.js 18+ recommended
- npm

## Run on Windows
1. Extract the ZIP.
2. Open the extracted `blockvault` folder in VS Code.
3. Open Terminal in that folder.
4. Run `npm install`
5. Run `npm start`
6. Open `http://localhost:3000`
7. Click **Create account**, register with your name, email, and account password, then sign in.

## Main features
- User registration and sign-in. Account passwords are salted and hashed with Node.js scrypt; passwords are not stored in plain text.
- Files are isolated by account in the file list and all file operations.
- Upload one file up to 200 MB.
- User-selectable 64 KB, 256 KB, 1 MB, or 4 MB blocks.
- Each block uses AES-256-GCM with a fresh random 12-byte IV and authenticated block index.
- Encryption key derived with PBKDF2-SHA256, 200,000 iterations, and a random 16-byte salt.
- Encrypted blocks and manifest stored in the local `cloud/` folder (simulated cloud storage).
- Download opaque `.enc` bundle without decrypting it.
- Restore/download the original after password and block integrity checks.
- **Open** decrypts and previews browser-supported image, PDF, text, audio, and video files in a new tab; other file types are decrypted and downloaded.
- Search, refresh, storage statistics, and delete actions.

## Data folders created automatically
- `data/users.json` — registered user profile data and password hashes. Created automatically after starting the server; do not publish this file.
- `cloud/<file-id>/` — encrypted block files and `manifest.json`. Created automatically on upload.
- `tmp/` — temporary uploads, removed after processing.

You do not need to create these folders or files manually. Keep `data/` and `cloud/` when you want to preserve registered accounts and encrypted files.

## Important notes
- `cloud/` is local storage simulating a cloud service, not AWS/Azure/GCP.
- Session tokens are held in server memory and expire when the server restarts; simply sign in again after restarting.
- This is a classroom demonstration, not production authentication. Use HTTPS, persistent secure sessions, rate limiting, CSRF protection, and a database before real deployment.
- Files uploaded with the earlier version have no account owner and therefore do not appear in the new account-based vault. Back up the old `cloud/` folder before replacing code if you need those files.
- Keep each file's encryption password safe. The account password and encryption password are separate: the account password signs you in; the encryption password is set per file.

## Main files
- `server.js` — auth endpoints, account-isolated file APIs, upload/download/decrypt/delete
- `lib/crypto.js` — PBKDF2, AES-256-GCM, and SHA-256 helpers
- `public/index.html` — login/register screen and redesigned dashboard
- `public/styles.css` — dashboard, responsive design, and auth UI
- `public/app.js` — all UI interactions and API calls

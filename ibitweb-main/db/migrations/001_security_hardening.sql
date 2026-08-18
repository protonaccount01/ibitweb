-- Security hardening migration.
-- Run with:  wrangler d1 execute <YOUR_DB_NAME> --file=db/migrations/001_security_hardening.sql
-- (add --remote once you've verified it locally, to apply it to production)

-- Real server-side sessions, replacing the forgeable `admin_auth=true` cookie.
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- Per-IP login rate limiting for /api/auth.
CREATE TABLE IF NOT EXISTS login_attempts (
    ip TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    window_start TEXT NOT NULL
);

-- IMPORTANT: the `users.password` column now stores a PBKDF2 hash string in
-- the form  pbkdf2$<iterations>$<saltBase64>$<hashBase64>
-- instead of a plaintext password. Existing plaintext rows will simply fail
-- to authenticate (verifyPassword() rejects anything not in that format) --
-- they will NOT be silently trusted. You must re-hash every existing user's
-- password using scripts/hash-password.js and UPDATE the row yourself, e.g.:
--
--   node scripts/hash-password.js "the-current-plaintext-password"
--   -> prints a pbkdf2$...$...$... string
--
--   wrangler d1 execute <YOUR_DB_NAME> --command \
--     "UPDATE users SET password = 'pbkdf2$100000$...$...' WHERE username = 'admin'"
--
-- Do this for every account before deploying, or that account will be
-- locked out (which is the safe failure mode, not a security hole).

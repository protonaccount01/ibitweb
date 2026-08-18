-- Base schema for the site.
-- Run this BEFORE 001_security_hardening.sql on a fresh D1 database.
--
--   wrangler d1 execute <YOUR_DB_NAME> --file=db/migrations/000_initial_schema.sql
--   wrangler d1 execute <YOUR_DB_NAME> --file=db/migrations/001_security_hardening.sql
--
-- NOTE: this table was referenced by functions/api/notices.js and
-- functions/api/auth.js, but no migration in this repo actually created
-- it — on a brand new D1 database every notice-board request and every
-- D1-table login would fail with "no such table". This file fixes that.

-- Notices shown on the homepage / notice board (see functions/api/notices.js).
CREATE TABLE IF NOT EXISTS notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    pdf_url TEXT,
    auto_delete_date TEXT,
    created_at TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_notices_created_at ON notices (created_at);

-- Only needed if you plan to use the D1 `users` table for admin login
-- (see functions/api/auth.js). Skip filling this in if you're using the
-- simpler ADMIN_USERNAME/ADMIN_PASSWORD env-var approach instead — see
-- SECURITY-CHANGES.md.
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);

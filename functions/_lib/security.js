/**
 * Shared security helpers for Cloudflare Pages Functions.
 *
 * Fixes applied here:
 *  - Real server-side sessions (random token stored in D1) instead of a
 *    forgeable `admin_auth=true` cookie.
 *  - PBKDF2-based password hashing (Web Crypto, natively available in
 *    Cloudflare Workers — no external dependency needed).
 *  - Basic IP-based rate limiting for the login endpoint.
 *  - A single place to attach security response headers.
 */

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = 'SHA-256';
const PBKDF2_KEYLEN_BYTES = 32;
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
const SESSION_COOKIE_NAME = 'session';
const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_WINDOW_SECONDS = 15 * 60; // 15 minutes

// ---------- encoding helpers ----------

function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function timingSafeEqual(a, b) {
    // Avoid an early-exit on length mismatch (that itself is a tiny timing
    // signal) by always comparing up to the longer of the two lengths.
    const maxLen = Math.max(a.length, b.length);
    let diff = a.length === b.length ? 0 : 1;
    for (let i = 0; i < maxLen; i++) {
        const ca = i < a.length ? a.charCodeAt(i) : 0;
        const cb = i < b.length ? b.charCodeAt(i) : 0;
        diff |= ca ^ cb;
    }
    return diff === 0;
}

// ---------- password hashing (PBKDF2 via Web Crypto) ----------

/**
 * Produces a self-describing hash string: pbkdf2$<iterations>$<saltB64>$<hashB64>
 * Compatible with scripts/hash-password.js (Node) since PBKDF2 is a standard
 * algorithm — identical inputs always produce identical output.
 */
export async function hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hashBytes = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
    return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(hashBytes)}`;
}

export async function verifyPassword(password, stored) {
    if (!stored || typeof stored !== 'string' || !stored.startsWith('pbkdf2$')) {
        // Legacy/plaintext row (pre-migration) — never treat as a match.
        // This forces an explicit re-hash via scripts/hash-password.js.
        return false;
    }
    const parts = stored.split('$');
    if (parts.length !== 4) return false;
    const iterations = parseInt(parts[1], 10);
    const salt = base64ToBytes(parts[2]);
    const expected = parts[3];
    const hashBytes = await pbkdf2(password, salt, iterations);
    const actual = bytesToBase64(hashBytes);
    return timingSafeEqual(actual, expected);
}

async function pbkdf2(password, salt, iterations) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations, hash: PBKDF2_HASH },
        keyMaterial,
        PBKDF2_KEYLEN_BYTES * 8
    );
    return new Uint8Array(bits);
}

/**
 * Constant-time comparison for a plaintext credential stored in a
 * Cloudflare "Secret" (encrypted) environment variable — e.g.
 * env.ADMIN_PASSWORD. This is a deliberate, supported alternative to
 * hashing: the secret is encrypted at rest by Cloudflare and only
 * decrypted into memory for the single Worker invocation that reads it,
 * it's never written to any database, and it never appears in the
 * dashboard UI once saved. Using timingSafeEqual (not `===`) still
 * matters here so a network-observable response-time difference can't be
 * used to guess the password one character at a time.
 */
export function verifyPlaintext(password, storedPlaintext) {
    if (typeof password !== 'string' || typeof storedPlaintext !== 'string') return false;
    return timingSafeEqual(password, storedPlaintext);
}

// ---------- sessions ----------

function randomToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Creates a session row in D1 and returns the raw token (not stored anywhere else). */
export async function createSession(env, username) {
    const token = randomToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
    await env.DB.prepare(
        'INSERT INTO sessions (token, username, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(token, username, expiresAt, new Date().toISOString()).run();
    return { token, expiresAt };
}

export function sessionCookieHeader(token, maxAgeSeconds = SESSION_TTL_SECONDS) {
    // HttpOnly -> not readable/forgeable from page JS (fixes the admin_auth bug).
    // Secure -> only sent over HTTPS. SameSite=Strict -> mitigates CSRF.
    return `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearSessionCookieHeader() {
    return `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

function readCookie(request, name) {
    const header = request.headers.get('Cookie') || '';
    const match = header.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
    return match ? match[1] : null;
}

/**
 * Validates the session cookie against D1. Returns { username } if valid, or null.
 * This replaces every previous `cookie.includes('admin_auth=true')` check.
 */
export async function requireSession(request, env) {
    const token = readCookie(request, SESSION_COOKIE_NAME);
    if (!token) return null;

    const row = await env.DB.prepare(
        'SELECT username, expires_at FROM sessions WHERE token = ?'
    ).bind(token).first();

    if (!row) return null;
    if (new Date(row.expires_at).getTime() < Date.now()) {
        // Expired — clean it up lazily.
        await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
        return null;
    }
    return { username: row.username, token };
}

export async function destroySession(request, env) {
    const token = readCookie(request, SESSION_COOKIE_NAME);
    if (token) {
        await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    }
}

/**
 * Sweeps rows that have naturally expired (old sessions, stale login-attempt
 * windows). Called opportunistically from the auth endpoint — cheap DELETE
 * with a WHERE clause, not a full scan — so these two tables stay small
 * forever without needing a separate Cron Trigger set up.
 */
export async function housekeeping(env) {
    const now = new Date().toISOString();
    const staleWindow = new Date(Date.now() - LOGIN_WINDOW_SECONDS * 1000).toISOString();
    try {
        await env.DB.batch([
            env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
            env.DB.prepare('DELETE FROM login_attempts WHERE window_start < ?').bind(staleWindow),
        ]);
    } catch (e) {
        // Never let housekeeping failure block a login/logout request.
    }
}

// ---------- login rate limiting (per IP, stored in D1) ----------

export async function checkRateLimit(env, ip) {
    const row = await env.DB.prepare(
        'SELECT attempts, window_start FROM login_attempts WHERE ip = ?'
    ).bind(ip).first();

    if (!row) return { blocked: false };

    const windowStart = new Date(row.window_start).getTime();
    const windowExpired = Date.now() - windowStart > LOGIN_WINDOW_SECONDS * 1000;

    if (windowExpired) return { blocked: false };
    if (row.attempts >= MAX_LOGIN_ATTEMPTS) {
        const retryAfter = Math.ceil((windowStart + LOGIN_WINDOW_SECONDS * 1000 - Date.now()) / 1000);
        return { blocked: true, retryAfter };
    }
    return { blocked: false };
}

export async function recordLoginFailure(env, ip) {
    const now = new Date().toISOString();
    const row = await env.DB.prepare('SELECT attempts, window_start FROM login_attempts WHERE ip = ?').bind(ip).first();

    if (!row) {
        await env.DB.prepare('INSERT INTO login_attempts (ip, attempts, window_start) VALUES (?, 1, ?)').bind(ip, now).run();
        return;
    }
    const windowStart = new Date(row.window_start).getTime();
    const windowExpired = Date.now() - windowStart > LOGIN_WINDOW_SECONDS * 1000;

    if (windowExpired) {
        await env.DB.prepare('UPDATE login_attempts SET attempts = 1, window_start = ? WHERE ip = ?').bind(now, ip).run();
    } else {
        await env.DB.prepare('UPDATE login_attempts SET attempts = attempts + 1 WHERE ip = ?').bind(ip).run();
    }
}

export async function clearLoginAttempts(env, ip) {
    await env.DB.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run();
}

export function getClientIp(request) {
    return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// ---------- Turnstile (optional CAPTCHA, only enforced if secret is configured) ----------

export async function verifyTurnstile(env, token, ip) {
    if (!env.TURNSTILE_SECRET_KEY) return true; // not configured -> skip (documented in README)
    if (!token) return false;
    try {
        const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip }),
        });
        const data = await res.json();
        return data.success === true;
    } catch (e) {
        return false;
    }
}

// ---------- security headers ----------

export function securityHeaders(extra = {}) {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        ...extra,
    };
}

export function jsonResponse(body, init = {}) {
    const headers = new Headers(init.headers || {});
    headers.set('Content-Type', 'application/json');
    for (const [k, v] of Object.entries(securityHeaders())) headers.set(k, v);
    return new Response(JSON.stringify(body), { ...init, headers });
}

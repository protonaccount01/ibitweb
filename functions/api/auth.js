import {
    verifyPassword, verifyPlaintext, createSession, sessionCookieHeader,
    checkRateLimit, recordLoginFailure, clearLoginAttempts,
    getClientIp, verifyTurnstile, jsonResponse, housekeeping
} from '../_lib/security.js';

/**
 * Two supported ways to configure the admin account — use whichever fits:
 *
 *  1. env.ADMIN_USERNAME + env.ADMIN_PASSWORD (plaintext), set as
 *     Cloudflare "Secret"/encrypted environment variables. Simplest option:
 *     no hashing step, no `users` table, no D1 write for credentials at
 *     all. Cloudflare encrypts the value at rest and never displays it
 *     again in the dashboard once saved — this is a legitimate, supported
 *     way to store a single admin credential.
 *
 *  2. The D1 `users` table, with a PBKDF2 hash in the `password` column
 *     (see scripts/hash-password.js / generate-admin-hash.html). Use this
 *     if you want more than one admin account.
 *
 * env vars are checked first. Both can coexist.
 */
async function lookupUser(env, username) {
    if (env.ADMIN_USERNAME && env.ADMIN_PASSWORD && username === env.ADMIN_USERNAME) {
        return { username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD, plaintext: true };
    }
    if (env.DB) {
        const row = await env.DB.prepare('SELECT username, password FROM users WHERE username = ?').bind(username).first();
        if (row) return { ...row, plaintext: false };
    }
    return null;
}

export async function onRequestPost(context) {
    const { request, env } = context;
    const ip = getClientIp(request);

    // Cheap opportunistic cleanup of expired sessions / stale rate-limit
    // windows, so these tables never grow unbounded over the site's lifetime
    // even if nobody ever runs a separate maintenance job.
    await housekeeping(env);

    // --- Rate limiting: block after too many failed attempts from this IP ---
    const rl = await checkRateLimit(env, ip);
    if (rl.blocked) {
        return jsonResponse(
            { success: false, message: 'Too many attempts. Try again later.' },
            { status: 429, headers: { 'Retry-After': String(rl.retryAfter) } }
        );
    }

    let body;
    try {
        body = await request.json();
    } catch (e) {
        return jsonResponse({ success: false, message: 'Invalid request' }, { status: 400 });
    }

    const { username, password, turnstileToken } = body;

    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return jsonResponse({ success: false, message: 'Invalid Credentials' }, { status: 401 });
    }

    // --- Optional CAPTCHA (no-op unless TURNSTILE_SECRET_KEY is configured) ---
    const captchaOk = await verifyTurnstile(env, turnstileToken, ip);
    if (!captchaOk) {
        return jsonResponse({ success: false, message: 'Captcha verification failed' }, { status: 401 });
    }

    const user = await lookupUser(env, username);

    let ok;
    if (user && user.plaintext) {
        ok = verifyPlaintext(password, user.password);
    } else {
        // Always run verifyPassword (even on a missing user) against a
        // dummy hash shape so response timing doesn't leak whether the
        // username exists.
        const storedHash = user ? user.password : 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
        ok = await verifyPassword(password, storedHash);
    }

    if (!user || !ok) {
        await recordLoginFailure(env, ip);
        return jsonResponse({ success: false, message: 'Invalid Credentials' }, { status: 401 });
    }

    await clearLoginAttempts(env, ip);
    const { token } = await createSession(env, user.username);

    return jsonResponse({ success: true }, {
        headers: { 'Set-Cookie': sessionCookieHeader(token) }
    });
}

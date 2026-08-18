#!/usr/bin/env node
/**
 * Generates a password hash in the exact format functions/_lib/security.js
 * expects: pbkdf2$<iterations>$<saltBase64>$<hashBase64>
 *
 * PBKDF2 is a standard algorithm, so Node's crypto.pbkdf2Sync here and Web
 * Crypto's subtle.deriveBits in the Workers runtime produce identical
 * output for the same password/salt/iterations/digest — this only needs to
 * be run once, offline, per password.
 *
 * Usage:
 *   node scripts/hash-password.js "your-new-password"
 *
 * Then copy the printed string into a D1 UPDATE/INSERT for the users table.
 * Never commit real passwords or hashes to source control.
 */
const crypto = require('crypto');

const ITERATIONS = 100000;
const KEYLEN = 32; // bytes
const DIGEST = 'sha256';

const password = process.argv[2];
if (!password) {
    console.error('Usage: node scripts/hash-password.js "<password>"');
    process.exit(1);
}

const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEYLEN, DIGEST);

const out = `pbkdf2$${ITERATIONS}$${salt.toString('base64')}$${hash.toString('base64')}`;
console.log(out);

import { requireSession, jsonResponse } from '../_lib/security.js';

// GET /api/session -> { authenticated: true/false }
// admin.html calls this on load instead of reading document.cookie
// (the session cookie is HttpOnly now, so it isn't even visible to JS —
// that's intentional, it's what stops it from being forged).
export async function onRequestGet(context) {
    const { request, env } = context;
    const session = await requireSession(request, env);
    return jsonResponse({ authenticated: !!session, username: session ? session.username : null });
}

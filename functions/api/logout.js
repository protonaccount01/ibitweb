import { destroySession, clearSessionCookieHeader, jsonResponse } from '../_lib/security.js';

// POST /api/logout -> invalidates the session row in D1 and clears the cookie.
// Needed because the cookie is HttpOnly now, so client JS can no longer
// clear it directly with `document.cookie = "admin_auth=; ..."`.
export async function onRequestPost(context) {
    const { request, env } = context;
    await destroySession(request, env);
    return jsonResponse({ success: true }, {
        headers: { 'Set-Cookie': clearSessionCookieHeader() }
    });
}

import { securityHeaders } from '../_lib/security.js';

// Only the filename shape our own upload.js ever generates is allowed
// through: "<digits>_<32 hex chars>.<ext>". Anything else is rejected
// before it ever reaches R2 — defense in depth against unexpected keys.
const SAFE_KEY = /^[0-9]+_[a-f0-9]{32}\.(pdf|jpg|png|webp)$/;

export async function onRequestGet(context) {
    const { env, params } = context;

    const key = params.path.join('/');
    if (!SAFE_KEY.test(key)) {
        return new Response('Not found', { status: 404 });
    }

    const object = await env.BUCKET.get(key);
    if (!object) return new Response('File not found', { status: 404 });

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('etag', object.httpEtag);
    // Belt-and-braces: even though upload.js already whitelists content
    // types, force the browser to never MIME-sniff a served file into
    // something executable (e.g. treating it as HTML).
    for (const [k, v] of Object.entries(securityHeaders())) headers.set(k, v);

    return new Response(object.body, { headers });
}

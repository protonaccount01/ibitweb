import { requireSession, jsonResponse } from '../_lib/security.js';

// Only these are ever accepted — attacker can no longer upload .html/.svg/.exe
// and have it served back from your domain.
const ALLOWED_TYPES = {
    'application/pdf': 'pdf',
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
};

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

function randomFileId() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequestPost(context) {
    const { request, env } = context;

    // --- Real session check (was the forgeable admin_auth cookie) ---
    const session = await requireSession(request, env);
    if (!session) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    let formData;
    try {
        formData = await request.formData();
    } catch (e) {
        return jsonResponse({ error: 'Invalid form data' }, { status: 400 });
    }

    const file = formData.get('file');
    if (!file || typeof file === 'string') return jsonResponse({ error: 'No file uploaded' }, { status: 400 });

    // --- Size limit ---
    if (file.size > MAX_FILE_SIZE) {
        return jsonResponse({ error: `File too large (max ${MAX_FILE_SIZE / 1024 / 1024}MB)` }, { status: 413 });
    }
    if (file.size === 0) {
        return jsonResponse({ error: 'Empty file' }, { status: 400 });
    }

    // --- Type whitelist: never trust the extension, only the declared MIME
    // type, and even that we map to our OWN extension + content-type below
    // rather than trusting the client's value verbatim. ---
    const safeExt = ALLOWED_TYPES[file.type];
    if (!safeExt) {
        return jsonResponse({ error: 'File type not allowed. Only PDF, JPG, PNG, WEBP are accepted.' }, { status: 415 });
    }

    // --- Fully random filename: no user-controlled characters end up in the
    // R2 key at all, so there's no path-traversal / collision / trickery
    // surface left in the filename. ---
    const fileName = `${Date.now()}_${randomFileId()}.${safeExt}`;

    await env.BUCKET.put(fileName, file.stream(), {
        httpMetadata: { contentType: file.type }, // safe: file.type was already checked against the whitelist above
    });

    return jsonResponse({ file_url: '/files/' + fileName });
}

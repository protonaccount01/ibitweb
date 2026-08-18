import { requireSession, jsonResponse } from '../_lib/security.js';

const MAX_TITLE_LEN = 300;
const MAX_CONTENT_LEN = 200000; // rich-text HTML from Quill can be sizable, but bounded
const MAX_URL_LEN = 500;

function validNoticePayload(body) {
    if (!body || typeof body !== 'object') return 'Invalid payload';
    if (!body.title || typeof body.title !== 'string' || body.title.trim().length === 0) return 'Title is required';
    if (body.title.length > MAX_TITLE_LEN) return `Title too long (max ${MAX_TITLE_LEN} chars)`;
    if (body.content && (typeof body.content !== 'string' || body.content.length > MAX_CONTENT_LEN)) return 'Content too long';
    if (body.pdf_url && (typeof body.pdf_url !== 'string' || body.pdf_url.length > MAX_URL_LEN)) return 'Invalid pdf_url';
    if (body.pdf_url && !body.pdf_url.startsWith('/files/')) return 'Invalid pdf_url';
    if (body.auto_delete_date && isNaN(Date.parse(body.auto_delete_date))) return 'Invalid auto_delete_date';
    return null;
}

export async function onRequest(context) {
    const { request, env } = context;
    const method = request.method;
    const url = new URL(request.url);

    try {
        if (method === 'GET') {
            const { results } = await env.DB.prepare('SELECT * FROM notices ORDER BY created_at DESC').all();
            return jsonResponse(results);
        }

        // --- All mutating operations require a valid server-side session ---
        // (Previously this checked `cookie.includes('admin_auth=true')`,
        // which anyone could set themselves. requireSession() validates the
        // token against the `sessions` table in D1.)
        const session = await requireSession(request, env);
        if (!session) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

        // Opportunistic cleanup of expired notices — only on writes, not on
        // every public GET, to avoid an extra D1 write on every page load.
        const now = new Date().toISOString();
        await env.DB.prepare('DELETE FROM notices WHERE auto_delete_date IS NOT NULL AND auto_delete_date < ?').bind(now).run();

        if (method === 'POST') {
            const body = await request.json();
            const err = validNoticePayload(body);
            if (err) return jsonResponse({ error: err }, { status: 400 });

            const dateVal = body.auto_delete_date ? body.auto_delete_date : null;
            await env.DB.prepare('INSERT INTO notices (title, content, auto_delete_date, pdf_url) VALUES (?, ?, ?, ?)')
                .bind(body.title.trim(), body.content || null, dateVal, body.pdf_url || null).run();
            return jsonResponse({ success: true });
        }

        if (method === 'PUT') {
            const body = await request.json();
            if (!body.id || isNaN(parseInt(body.id, 10))) return jsonResponse({ error: 'Invalid id' }, { status: 400 });
            const err = validNoticePayload(body);
            if (err) return jsonResponse({ error: err }, { status: 400 });

            const dateVal = body.auto_delete_date ? body.auto_delete_date : null;
            await env.DB.prepare('UPDATE notices SET title = ?, content = ?, auto_delete_date = ?, pdf_url = ? WHERE id = ?')
                .bind(body.title.trim(), body.content || null, dateVal, body.pdf_url || null, parseInt(body.id, 10)).run();
            return jsonResponse({ success: true });
        }

        if (method === 'DELETE') {
            const idParam = url.searchParams.get('id');
            const id = parseInt(idParam, 10);
            if (!idParam || isNaN(id)) return jsonResponse({ error: 'Invalid id' }, { status: 400 });

            const notice = await env.DB.prepare('SELECT pdf_url FROM notices WHERE id = ?').bind(id).first();
            if (notice && notice.pdf_url) {
                const key = notice.pdf_url.replace('/files/', '');
                await env.BUCKET.delete(key);
            }
            await env.DB.prepare('DELETE FROM notices WHERE id = ?').bind(id).run();
            return jsonResponse({ success: true });
        }

        return jsonResponse({ error: 'Method not allowed' }, { status: 405 });
    } catch (error) {
        return jsonResponse({ error: 'Internal error' }, { status: 500 });
    }
}

/**
 * sanitizeHtml(dirty) — allowlist-based HTML sanitizer.
 *
 * Why not DOMPurify from a CDN? Loading a third-party script for the ONE
 * thing that renders admin-authored HTML into every visitor's browser is
 * itself a supply-chain risk (see the SRI finding in the audit report).
 * This sanitizer has no external dependency, so there's nothing to
 * compromise or MITM. It's intentionally conservative: it only allows the
 * tags/attributes the Quill editor in admin.html actually produces, and
 * strips everything else (script/style/iframe/object/embed/on* handlers/
 * javascript: URLs/etc.) unconditionally.
 *
 * Used anywhere notice.content (rich text) is rendered: pages/notice.html
 * and the admin preview in auth/admin.html.
 */
(function (global) {
    const ALLOWED_TAGS = new Set([
        'P', 'BR', 'STRONG', 'B', 'EM', 'I', 'U', 'S', 'STRIKE', 'SPAN',
        'H1', 'H2', 'H3', 'H4', 'UL', 'OL', 'LI', 'BLOCKQUOTE', 'PRE', 'CODE',
        'A', 'IMG', 'HR', 'DIV', 'SUB', 'SUP'
    ]);

    const ALLOWED_ATTRS = {
        'A': ['href', 'target', 'rel'],
        'IMG': ['src', 'alt', 'width', 'height'],
        'SPAN': ['class'],
        'DIV': ['class'],
        'P': ['class'],
    };

    function isSafeUrl(value) {
        if (!value) return false;
        const v = value.trim().toLowerCase();
        // Only allow http(s), relative paths, and mailto — never javascript:,
        // data:, vbscript:, or anything else that can execute code.
        if (v.startsWith('javascript:') || v.startsWith('data:') || v.startsWith('vbscript:')) return false;
        return /^(https?:\/\/|\/|mailto:|#)/i.test(v);
    }

    function sanitizeNode(node) {
        // Text nodes are always safe as-is.
        if (node.nodeType === Node.TEXT_NODE) return node.cloneNode(true);

        if (node.nodeType !== Node.ELEMENT_NODE) return null; // drop comments, etc.

        const tag = node.tagName;
        if (!ALLOWED_TAGS.has(tag)) {
            // Not an allowed element — but keep sanitized children as a
            // fragment so legitimate nested text isn't lost, e.g. a stray
            // <script> is dropped entirely (including its text content),
            // while an unknown wrapper like <font> just gets unwrapped.
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'IFRAME' || tag === 'OBJECT' || tag === 'EMBED' || tag === 'FORM') {
                return null;
            }
            const frag = document.createDocumentFragment();
            node.childNodes.forEach(child => {
                const clean = sanitizeNode(child);
                if (clean) frag.appendChild(clean);
            });
            return frag;
        }

        const el = document.createElement(tag);
        const allowedAttrs = ALLOWED_ATTRS[tag] || [];

        for (const attr of Array.from(node.attributes)) {
            const name = attr.name.toLowerCase();
            if (name.startsWith('on')) continue; // strip ALL event handlers, always
            if (!allowedAttrs.includes(name)) continue;

            if ((name === 'href' || name === 'src') && !isSafeUrl(attr.value)) continue;

            el.setAttribute(name, attr.value);
        }

        // Force safe defaults for links so an <a> can never be used to
        // pivot into a same-tab phishing redirect with access to window.opener.
        if (tag === 'A') {
            el.setAttribute('rel', 'noopener noreferrer');
            if (el.getAttribute('target') === '_blank') el.setAttribute('target', '_blank');
        }

        node.childNodes.forEach(child => {
            const clean = sanitizeNode(child);
            if (clean) el.appendChild(clean);
        });

        return el;
    }

    function sanitizeHtml(dirty) {
        if (!dirty) return '';
        const template = document.createElement('template');
        template.innerHTML = String(dirty);

        const frag = document.createDocumentFragment();
        template.content.childNodes.forEach(child => {
            const clean = sanitizeNode(child);
            if (clean) frag.appendChild(clean);
        });

        const wrapper = document.createElement('div');
        wrapper.appendChild(frag);
        return wrapper.innerHTML;
    }

    global.sanitizeHtml = sanitizeHtml;
})(window);

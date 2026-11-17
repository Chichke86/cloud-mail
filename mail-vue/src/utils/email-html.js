import DOMPurify from 'dompurify'

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'IMG') {
        const src = node.getAttribute('src') || ''
        if (!/^(?:\{\{domain\}\}|\/api\/files\/)attachments\/(?:[a-f0-9]{32}|[a-f0-9]{64})(?:\.[A-Za-z0-9_+-]{1,32})?$/.test(src)) {
            node.removeAttribute('src')
        }
        return
    }
    if (node.tagName !== 'A') return
    node.setAttribute('target', '_blank')
    const rel = new Set((node.getAttribute('rel') || '').split(/\s+/).filter(Boolean))
    rel.add('noopener')
    rel.add('noreferrer')
    node.setAttribute('rel', [...rel].join(' '))
})

export function sanitizeEmailHtml(html) {
    if (!html) return html
    return DOMPurify.sanitize(html, {
        WHOLE_DOCUMENT: true,
        ADD_ATTR: ['target'],
        FORBID_TAGS: ['style', 'form', 'input', 'button', 'meta', 'base', 'link', 'video', 'audio', 'source', 'svg', 'math'],
        FORBID_ATTR: ['style', 'srcset', 'background', 'ping'],
    })
}

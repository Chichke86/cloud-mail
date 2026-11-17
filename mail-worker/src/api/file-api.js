import app from '../hono/hono';
import r2Service from '../service/r2-service';
import permService from '../service/perm-service';
import { attachmentKey } from '../security/file-key';

const inlineImages = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp', 'image/avif']);

app.get('/files/attachments/:name', async (c) => {
	const key = 'attachments/' + c.req.param('name');
	if (!attachmentKey.test(key)) return c.notFound();
	const { userId, email } = c.get('user');
	const canReadAll = email === c.env.admin || (await permService.userPermKeys(c, userId)).includes('all-email:query');
	// The key is a content hash used for deduplication, not a credential.
	const row = await c.env.db.prepare(`SELECT a.filename, a.mime_type AS mimeType
		FROM attachments a JOIN email e ON e.email_id = a.email_id AND e.user_id = a.user_id
		WHERE a.key = ? AND (e.user_id = ? OR ? = 1)
		ORDER BY (e.user_id = ?) DESC, a.att_id LIMIT 1`)
		.bind(key, userId, Number(canReadAll), userId).first();
	if (!row) return c.notFound();
	const object = await r2Service.toObjResp(c, key);
	if (!object?.ok) return c.notFound();
	const inline = c.req.query('download') !== '1' && inlineImages.has(row.mimeType);
	const name = encodeURIComponent((row.filename || 'attachment').toWellFormed())
		.replace(/['()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16));
	return c.body(object.body, 200, {
		'Content-Type': inline ? row.mimeType : 'application/octet-stream',
		'Content-Disposition': (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + name,
		'Content-Security-Policy': "default-src 'none'; sandbox",
		'Cross-Origin-Resource-Policy': 'same-origin',
	});
});

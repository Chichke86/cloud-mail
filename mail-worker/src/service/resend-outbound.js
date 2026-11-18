import { Buffer } from 'node:buffer';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

export function resendSender(env) {
	const from = typeof env.RESEND_FROM === 'string' ? env.RESEND_FROM.trim().toLowerCase() : '';
	return typeof env.RESEND_API_KEY === 'string' && env.RESEND_API_KEY.trim() &&
		/^[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}$/.test(from) ? from : null;
}

export async function sendResend(env, params, attachments) {
	const from = resendSender(env);
	if (!from || from !== params.accountEmail.toLowerCase()) {
		throw new BizError(t('noSendProvider'));
	}

	const { receiveEmail, ccEmail, bccEmail, subject, text, html, sendType, messageId } = params;
	const payload = { from, to: receiveEmail, subject, text, html };
	if (ccEmail.length) payload.cc = ccEmail;
	if (bccEmail.length) payload.bcc = bccEmail;
	if (sendType === 'reply' && typeof messageId === 'string' && messageId.length <= 998 &&
		/^<[^<>\s\x00-\x1f\x7f]+>$/.test(messageId)) {
		payload.headers = { 'In-Reply-To': messageId, References: messageId };
	}
	if (attachments.length) {
		payload.attachments = attachments.map(item => ({
			filename: item.filename,
			content: Buffer.from(item.content).toString('base64'),
			content_type: item.mimeType || item.contentType || item.type || 'application/octet-stream',
			...(item.contentId ? { content_id: item.contentId.replace(/^<|>$/g, '') } : {})
		}));
	}

	try {
		const request = new Request('https://api.resend.com/emails', {
			method: 'POST',
			headers: { Authorization: `Bearer ${env.RESEND_API_KEY.trim()}`, 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
			// Workers supports manual redirects. Any 3xx is rejected below without forwarding the key.
			redirect: 'manual',
			signal: AbortSignal.timeout(10_000)
		});
		const response = await fetch(request);
		if (!response.ok) {
			await response.body?.cancel();
			if (response.status === 429) throw new BizError(t('resendSendLimit'), 429);
		} else {
			const { id } = await response.json();
			if (typeof id === 'string' && id.length > 0 && id.length <= 128) return { data: { id } };
		}
	} catch (error) {
		if (error instanceof BizError) throw error;
		// Provider bodies and transport errors may contain sensitive request data.
	}
	throw new BizError(t('resendSendFailed'), 502);
}

import production from '../src/index';
import bootstrap from '../src/bootstrap-local';
export { MailHub } from '../src/index';

// Capture the provider wire format in workerd without permitting real network calls.
const resendRequests = [];
globalThis.fetch = async (url, options) => {
	if (url !== 'https://api.resend.com/emails') throw new Error('Unexpected outbound request');
	const payload = JSON.parse(options.body);
	resendRequests.push({
		method: options.method,
		authorized: options.headers.Authorization === 'Bearer re_synthetic_test',
		redirect: options.redirect,
		payload,
	});
	if (payload.subject === 'Provider quota') {
		return new Response('sensitive provider response', { status: 429 });
	}
	if (payload.subject === 'Provider failure') throw new Error('sensitive transport failure');
	return Response.json({ id: 'provider-fixture-id' });
};

export default {
	...production,
	fetch(request, env, ctx) {
		const path = new URL(request.url).pathname;
		if (path === '/resend-fixture') return Response.json(resendRequests);
		return path === '/bootstrap'
			? bootstrap.fetch(request, env)
			: production.fetch(request, env, ctx);
	},
};

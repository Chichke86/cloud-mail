import production from '../src/index';
import bootstrap from '../src/bootstrap-local';
export { MailHub } from '../src/index';

// Capture the provider wire format in workerd without permitting real network calls.
const resendRequests = [];
let accessKeys;
globalThis.fetch = async (request) => {
	if (request === 'https://fixture-team.cloudflareaccess.com/cdn-cgi/access/certs' && accessKeys) {
		return Response.json(accessKeys);
	}
	if (!(request instanceof Request) || request.url !== 'https://api.resend.com/emails') {
		throw new Error('Unexpected outbound request');
	}
	const payload = await request.json();
	resendRequests.push({
		method: request.method,
		authorized: request.headers.get('Authorization') === 'Bearer re_synthetic_test',
		redirect: request.redirect,
		payload,
	});
	if (payload.subject === 'Provider quota') {
		return new Response('sensitive provider response', { status: 429 });
	}
	if (payload.subject === 'Provider failure') throw new Error('sensitive transport failure');
	if (payload.subject === 'Provider redirect') return Response.redirect('https://example.test/redirect', 307);
	return Response.json({ id: 'provider-fixture-id' });
};

export default {
	...production,
	fetch(request, env, ctx) {
		const path = new URL(request.url).pathname;
		if (path === '/resend-fixture') return Response.json(resendRequests);
		if (path === '/bootstrap' && env.ACCESS_FIXTURE_JWKS) {
			accessKeys = JSON.parse(env.ACCESS_FIXTURE_JWKS);
		}
		return path === '/bootstrap'
			? bootstrap.fetch(request, env)
			: production.fetch(request, env, ctx);
	},
};

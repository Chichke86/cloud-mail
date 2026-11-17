export async function limit(c, binding, key) {
	// Missing limits are a configuration error, not permission to bypass throttling.
	if (!c.env[binding]?.limit) throw new Error('Rate limiter binding missing');
	return (await c.env[binding].limit({ key })).success;
}

export function isSameOrigin(request) {
	const expected = new URL(request.url).origin;
	const origin = request.headers.get('Origin');
	const site = request.headers.get('Sec-Fetch-Site');
	return (!origin || origin === expected) && (!site || site === 'same-origin' || site === 'none');
}

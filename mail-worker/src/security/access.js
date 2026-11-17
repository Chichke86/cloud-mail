import { createRemoteJWKSet, jwtVerify } from 'jose';

export function authMode(env) {
	return env.AUTH_MODE === undefined || env.AUTH_MODE === 'password' ? 'password'
		: env.AUTH_MODE === 'access' ? 'access' : 'invalid';
}

// Only trusted Worker configuration selects the issuer, key URL and mailbox.
// Keep one verifier per isolate and let jose handle key rotation and timeouts.
let cached;
export async function verifyAccess(c) {
	const { ACCESS_TEAM, ACCESS_AUD, ACCESS_IDENTITY, admin } = c.env;
	const token = c.req.header('Cf-Access-Jwt-Assertion');
	if (!token || token.length > 8192 || typeof ACCESS_TEAM !== 'string' ||
		!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(ACCESS_TEAM) ||
		typeof ACCESS_AUD !== 'string' || !/^[0-9a-f]{64}$/.test(ACCESS_AUD) ||
		typeof ACCESS_IDENTITY !== 'string' || !ACCESS_IDENTITY.includes('@') ||
		typeof admin !== 'string' || !admin.includes('@')) return null;

	const issuer = `https://${ACCESS_TEAM}.cloudflareaccess.com`;
	try {
		if (cached?.issuer !== issuer) {
			cached = {
				issuer,
				jwks: createRemoteJWKSet(new URL('/cdn-cgi/access/certs', issuer), { timeoutDuration: 3000 }),
			};
		}
		const { payload } = await jwtVerify(token, cached.jwks, {
			issuer, audience: ACCESS_AUD, algorithms: ['RS256'],
			requiredClaims: ['exp', 'iat', 'nbf', 'email', 'type'],
		});
		if (payload.type !== 'app' || typeof payload.email !== 'string' ||
			payload.email.toLowerCase() !== ACCESS_IDENTITY.toLowerCase()) return null;
		return { expiresAt: payload.exp };
	} catch {
		return null;
	}
}

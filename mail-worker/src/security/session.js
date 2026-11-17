import { getCookie, setCookie } from 'hono/cookie';
import { Buffer } from 'node:buffer';

const cookie = '__Host-wisereply_session';
const ttl = 8 * 60 * 60;
const digest = async (token) => Buffer.from(await crypto.subtle.digest('SHA-256',
	new TextEncoder().encode(token))).toString('hex');
const cookieOptions = { path: '/', secure: true, httpOnly: true, sameSite: 'Strict' };
const now = () => Math.floor(Date.now() / 1000);

export async function startSession(c, user, expiresAt = Infinity) {
	const start = now();
	const maxAge = Math.min(ttl, Math.floor(expiresAt) - start);
	if (maxAge <= 0) return false;
	const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
	const created = await c.env.db.prepare(`INSERT INTO wisereply_session(token_hash, user_id, expires_at)
		SELECT ?, user_id, ? FROM user WHERE user_id = ? AND password = ? AND status = 0 AND is_del = 0`)
		.bind(await digest(token), start + maxAge, user.userId, user.password).run();
	if (created.meta.changes !== 1) return false;
	setCookie(c, cookie, token, { ...cookieOptions, maxAge });
	return true;
}

export async function getSession(env, hash) {
	if (!/^[0-9a-f]{64}$/.test(hash || '')) return null;
	// Use D1 directly, not eventually-consistent KV, for revocation and current user state.
	return env.db.prepare(`SELECT u.user_id AS userId, u.email, u.type FROM wisereply_session s
		JOIN user u ON u.user_id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_del = 0 AND u.status = 0`)
		.bind(hash, now()).first();
}

export async function authenticate(c) {
	const token = getCookie(c, cookie);
	if (!/^[A-Za-z0-9_-]{43}$/.test(token || '')) return null;
	const hash = await digest(token);
	const user = await getSession(c.env, hash);
	if (user) c.set('sessionHash', hash);
	return user;
}

export async function endSession(c) {
	const hash = c.get('sessionHash');
	if (hash) await c.env.db.prepare('DELETE FROM wisereply_session WHERE token_hash = ?').bind(hash).run();
	setCookie(c, cookie, '', { ...cookieOptions, maxAge: 0 });
}

export async function clearExpiredSessions(env) {
	await env.db.prepare('DELETE FROM wisereply_session WHERE expires_at <= ?').bind(now()).run();
}

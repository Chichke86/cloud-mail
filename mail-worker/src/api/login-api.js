import app from '../hono/hono';
import userService from '../service/user-service';
import cryptoUtils from '../utils/crypto-utils';
import result from '../model/result';
import { endSession, startSession } from '../security/session';
import { limit } from '../security/request-policy';

app.post('/login', async (c) => {
	const ip = c.req.header('CF-Connecting-IP') || 'unknown';
	if (!await limit(c, 'LOGIN_LIMIT', 'ip:' + ip)) return c.json(result.fail('Try again later', 429), 429);
	let params;
	try { params = await c.req.json(); } catch {
		return c.json(result.fail('Invalid request', 400), 400);
	}
	const email = typeof params?.email === 'string' ? params.email.trim().toLowerCase() : '';
	const password = params?.password;
	const rejected = () => c.json(result.fail('Invalid email or password', 401), 401);
	if (!email || email.length > 254 || !cryptoUtils.validPassword(password)) return rejected();
	if (!await limit(c, 'LOGIN_LIMIT', 'account:' + email)) return c.json(result.fail('Try again later', 429), 429);
	const user = await userService.selectByEmailIncludeDel(c, email);
	// Make unknown, disabled, and legacy accounts follow the expensive verification path too.
	const enabled = user?.status === 0 && user.isDel === 0 && user.password.startsWith('scrypt-v1:');
	const salt = enabled ? user.salt : 'AAAAAAAAAAAAAAAAAAAAAA==';
	const hash = enabled ? user.password : 'scrypt-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
	if (!await cryptoUtils.verifyPassword(password, salt, hash) || !enabled) return rejected();
	// Replace this browser's previous session if it was logged in.
	if (c.get('sessionHash')) await endSession(c);
	if (!await startSession(c, user)) return rejected();
	return c.json(result.ok({ token: 'session' }));
});

app.delete('/logout', async (c) => {
	await endSession(c);
	return c.json(result.ok());
});

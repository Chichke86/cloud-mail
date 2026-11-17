// Local tooling entry only. Never configure a hosted Worker with this file.
import { dbInit } from './init/init';
import cryptoUtils from './utils/crypto-utils';
import { timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
export { MailHub } from './websocket/hub'; // The local Wrangler config declares this binding.

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const input = request.headers.get('Authorization') || '';
		const secret = env.BOOTSTRAP_SECRET;
		if (request.method !== 'POST' || url.pathname !== '/bootstrap' ||
			!['localhost', '127.0.0.1'].includes(url.hostname) ||
			!/^[a-f0-9]{64}$/.test(secret || '') || !/^[a-f0-9]{64}$/.test(input) ||
			!timingSafeEqual(Buffer.from(input), Buffer.from(secret))) {
			return new Response(null, { status: 404 });
		}
		const password = env.BOOTSTRAP_PASSWORD;
		if (!cryptoUtils.validPassword(password) || password.length < 15 ||
			!env.domain.includes(env.admin.split('@').at(-1))) return new Response(null, { status: 400 });
		const hasUsers = await env.db.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'user'").first();
		if (hasUsers && await env.db.prepare('SELECT 1 FROM user LIMIT 1').first()) return new Response(null, { status: 409 });
		await dbInit.init({ env });
		const { salt, hash } = await cryptoUtils.hashPassword(password);
		const { roleId } = await env.db.prepare('SELECT role_id AS roleId FROM role WHERE is_default = 1 LIMIT 1').first();
		await env.db.batch([
			env.db.prepare('INSERT INTO user(email, password, salt, type) VALUES (?, ?, ?, ?)')
				.bind(env.admin, hash, salt, roleId),
			env.db.prepare('INSERT INTO account(email, name, user_id) VALUES (?, ?, (SELECT user_id FROM user WHERE email = ?))')
				.bind(env.admin, env.admin.split('@')[0], env.admin),
		]);
		return new Response(null, { status: 204 });
	},
};

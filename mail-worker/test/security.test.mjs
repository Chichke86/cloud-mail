import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';

const secret = randomBytes(32).toString('hex');
const password = 'A test password with enough length';
const admin = 'admin@wisereply.example';
const owner = "o'neal@wisereply.example";
const peer = 'peer@wisereply.example';
const origin = 'https://localhost';
const legacy = 'legacy@wisereply.example';
const server = createTestHarness({
	workers: [{ config: {
		name: 'wisereply-security-test', main: 'test/entry.js',
		compatibility_date: '2025-06-04', compatibility_flags: ['nodejs_compat'],
		d1_databases: [{ binding: 'db', database_id: '00000000-0000-4000-8000-000000000011' }],
		kv_namespaces: [{ binding: 'kv', id: '00000000000000000000000000000012' }],
		r2_buckets: [{ binding: 'r2', bucket_name: 'security-test-local' }],
		durable_objects: { bindings: [{ name: 'ws', class_name: 'MailHub' }] },
		migrations: [{ tag: 'v1', new_sqlite_classes: ['MailHub'] }],
		ratelimits: [
			{ name: 'LOGIN_LIMIT', namespace_id: '73100411', simple: { limit: 8, period: 60 } },
			{ name: 'API_LIMIT', namespace_id: '73100412', simple: { limit: 180, period: 60 } },
		],
		vars: { admin, domain: ['wisereply.example'], BOOTSTRAP_SECRET: secret, BOOTSTRAP_PASSWORD: password },
	} }],
});

const worker = server.getWorker();
let env;
let adminCookie;
let ownerCookie;
let peerCookie;
let ownerId;
const fileKey = 'attachments/' + 'a'.repeat(64) + '.html';
const fileRoute = '/api/files/' + fileKey;
const call = (path, options = {}) => worker.fetch(origin + path, options);
const auth = (cookie, extra = {}) => ({ Cookie: cookie, ...extra });
const json = (body, headers = {}, method = 'POST') => ({
	method, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
});

async function expectOk(response) {
	assert.equal(response.status, 200, await response.clone().text());
	const result = await response.json();
	assert.equal(result.code, 200, JSON.stringify(result));
	return result.data;
}

async function signIn(email, value = password, extra = {}) {
	const response = await call('/api/login', json({ email, password: value },
		{ 'CF-Connecting-IP': '192.0.2.1', ...extra }));
	assert.equal(response.status, 200, await response.clone().text());
	const header = response.headers.get('Set-Cookie');
	assert.match(header, /__Host-wisereply_session=[-\w]{43}/);
	assert.match(header, /; Secure/i);
	assert.match(header, /; HttpOnly/i);
	assert.match(header, /; SameSite=Strict/i);
	assert.deepEqual((await response.json()).data, { token: 'session' });
	return header.split(';')[0];
}

before(async () => {
	await server.listen();
	assert.equal((await call('/bootstrap', { method: 'POST' })).status, 404);
	assert.equal((await call('/bootstrap', { method: 'POST', headers: { Authorization: secret } })).status, 204);
	env = await worker.getEnv();
	adminCookie = await signIn(admin);
	for (const email of [owner, peer]) {
		await expectOk(await call('/api/user/add', json({ email, password }, auth(adminCookie))));
	}
	ownerCookie = await signIn(owner);
	peerCookie = await signIn(peer);
	const u = await env.db.prepare('SELECT user_id AS id FROM user WHERE email = ?').bind(owner).first();
	ownerId = u.id;
	const acc = await env.db.prepare('SELECT account_id AS id FROM account WHERE user_id = ?').bind(ownerId).first();
	const email = await env.db.prepare('INSERT INTO email(account_id, user_id) VALUES (?, ?) RETURNING email_id AS id')
		.bind(acc.id, ownerId).first();
	await env.db.prepare('INSERT INTO attachments(user_id, email_id, account_id, key, filename, mime_type) VALUES (?, ?, ?, ?, ?, ?)')
		.bind(ownerId, email.id, acc.id, fileKey, "owner's file.html", 'text/html').run();
	await env.r2.put(fileKey, 'synthetic attachment');
});
after(() => server.close());

test('bootstraps an admin and provisions a quote-bearing email safely; stores distinct scrypt hashes', async () => {
	const rows = (await env.db.prepare('SELECT email, password, salt FROM user ORDER BY user_id').all()).results;
	assert.deepEqual(rows.map(row => row.email), [admin, owner, peer]);
	assert.equal(new Set(rows.map(row => row.salt)).size, rows.length);
	for (const row of rows) assert.match(row.password, /^scrypt-v1:[\w+/]{43}=$/);
	assert.equal(JSON.stringify(await expectOk(await call('/api/my/loginUserInfo', { headers: auth(ownerCookie) })))
		.includes('scrypt-v1:'), false);
});

test('legacy hashes, invalid credentials, and header-only login sessions fail closed', async () => {
	await env.db.prepare('INSERT INTO user(email, password, salt, type) VALUES (?, ?, ?, 1)')
		.bind(legacy, 'old-sha256-record', 'legacy-salt').run();
	for (const [email, value] of [[legacy, password], [owner, 'incorrect'], ['unknown@wisereply.example', password]]) {
		const response = await call('/api/login', json({ email, password: value }, { 'CF-Connecting-IP': '192.0.2.3' }));
		assert.equal(response.status, 401);
		assert.equal(response.headers.get('Set-Cookie'), null);
	}
	assert.equal((await call('/api/my/loginUserInfo', { headers: { Authorization: ownerCookie } })).status, 401);
});

test('private objects are streamed only to authorized mailboxes and cannot execute HTML', async () => {
	assert.equal((await call(fileRoute)).status, 401);
	assert.equal((await call(fileRoute, { headers: auth(peerCookie) })).status, 404);
	const response = await call(fileRoute, { headers: auth(ownerCookie) });
	assert.equal(response.status, 200);
	assert.equal(await response.text(), 'synthetic attachment');
	assert.equal(response.headers.get('Content-Type'), 'application/octet-stream');
	assert.match(response.headers.get('Content-Disposition'), /^attachment; filename\*=UTF-8''owner%27s/);
	assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
	assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
	assert.equal((await call(fileRoute, { headers: auth(adminCookie) })).status, 200);
});

test('registration, raw object serving, bootstrap-as-API, and integrations stay disabled', async () => {
	for (const path of ['/api/register', '/api/public/genToken', '/api/test', '/api/oauth', '/api/webhooks',
		'/api/telegram/getEmail/test', '/api/init/test', '/api/bootstrap', '/' + fileKey,
		'/oss/' + fileKey, '/api/oss/' + fileKey, '/static/background/hidden.png']) {
		assert.equal((await call(path, { headers: auth(adminCookie) })).status, 404, path);
	}
	assert.equal((await call('/api/register', json({ email: peer, password }))).status, 404);
	assert.equal((await expectOk(await call('/api/setting/websiteConfig'))).register, 1);
});

test('non-admin cannot manage users or access all mail; cross-origin reads and writes are blocked', async () => {
	for (const path of ['/api/user/list', '/api/setting/query', '/api/role/list', '/api/allEmail/list']) {
		assert.equal((await call(path, { headers: auth(peerCookie) })).status, 403, path);
	}
	const foreign = { Origin: 'https://unrelated.example', 'Sec-Fetch-Site': 'cross-site' };
	const rejected = await call(fileRoute, { headers: auth(ownerCookie, foreign) });
	assert.equal(rejected.status, 403);
	assert.equal(rejected.headers.get('Access-Control-Allow-Origin'), null);
	assert.equal((await call('/api/logout', { method: 'DELETE', headers: auth(ownerCookie, foreign) })).status, 403);
	assert.equal((await call('/api/login', { method: 'OPTIONS', headers: foreign })).status, 403);
});

test('login throttles before password verification and enforces body size', async () => {
	for (let i = 0; i < 8; i++) {
		assert.equal((await call('/api/login', json({}, { 'CF-Connecting-IP': '192.0.2.4' }))).status, 401);
	}
	assert.equal((await call('/api/login', json({}, { 'CF-Connecting-IP': '192.0.2.4' }))).status, 429);
	assert.equal((await call('/api/login', json({ email: admin, password: 'x'.repeat(8200) }))).status, 413);
});

test('local Email Routing ingests a synthetic message for the intended mailbox', async () => {
	const sent = await worker.email({ from: 'sender@example.test', to: peer,
		raw: 'From: sender@example.test\r\nTo: ' + peer + '\r\nMessage-ID: <fixture@example.test>\r\nSubject: Local routing fixture\r\n\r\nSynthetic body' });
	assert.equal(sent.rejected, undefined);
	const stored = await env.db.prepare('SELECT subject, to_email AS address FROM email WHERE subject = ?')
		.bind('Local routing fixture').first();
	assert.deepEqual(stored, { subject: 'Local routing fixture', address: peer });
});

test('password reset revokes all prior sessions and logout invalidates the current session', async () => {
	const newPassword = 'A different long synthetic password';
	await expectOk(await call('/api/my/resetPassword', json({ password: newPassword }, auth(ownerCookie), 'PUT')));
	assert.equal((await call(fileRoute, { headers: auth(ownerCookie) })).status, 401);
	const replacement = await signIn(owner, newPassword);
	assert.equal((await call(fileRoute, { headers: auth(replacement) })).status, 200);
	await expectOk(await call('/api/logout', { method: 'DELETE', headers: auth(replacement) }));
	assert.equal((await call(fileRoute, { headers: auth(replacement) })).status, 401);
});

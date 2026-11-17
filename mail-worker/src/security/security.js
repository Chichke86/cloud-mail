import BizError from '../error/biz-error';
import permService from '../service/perm-service';
import app from '../hono/hono';
import { authenticate } from './session';
import { isSameOrigin, limit } from './request-policy';

const publicRoutes = new Set(['POST /login', 'GET /setting/websiteConfig']);
const permissions = new Map([
	['POST /email/send', 'email:send'],
	['DELETE /email/delete', 'email:delete'],
	['GET /account/list', 'account:query'],
	['POST /account/add', 'account:add'],
	['DELETE /account/delete', 'account:delete'],
	['DELETE /my/delete', 'my:delete'],
	['GET /analysis/echarts', 'analysis:query'],
	['GET /allEmail/list', 'all-email:query'],
	['GET /allEmail/latest', 'all-email:query'],
	['DELETE /allEmail/delete', 'all-email:delete'],
	['DELETE /allEmail/batchDelete', 'all-email:delete'],
]);
const authenticatedRoutes = new Set([
	'DELETE /logout', 'GET /my/loginUserInfo', 'PUT /my/resetPassword',
	'GET /email/list', 'GET /email/latest', 'GET /email/attList', 'PUT /email/read',
	'PUT /account/setName', 'PUT /account/setAllReceive', 'PUT /account/setAsTop',
	'GET /star/list', 'POST /star/add', 'DELETE /star/cancel', 'GET /realtime',
]);

app.use('*', async (c, next) => {
	c.header('Cache-Control', 'private, no-store');
	c.header('X-Content-Type-Options', 'nosniff');
	if (!isSameOrigin(c.req.raw)) throw new BizError('Cross-origin requests are disabled', 403);
	const { path, method } = c.req;
	const route = method + ' ' + path;
	const isPublic = publicRoutes.has(route);
	const adminOnly = /^\/(user|role|setting)(\/|$)/.test(path) && !isPublic;
	const file = method === 'GET' && path.startsWith('/files/');
	if (!(isPublic || adminOnly || file || permissions.has(route) || authenticatedRoutes.has(route))) {
		return c.notFound();
	}
	if (route === 'GET /setting/websiteConfig') {
		const ip = c.req.header('CF-Connecting-IP') || 'unknown';
		if (!await limit(c, 'API_LIMIT', 'public:' + ip)) throw new BizError('Try again later', 429);
		return next();
	}

	const user = await authenticate(c);
	if (isPublic) return next();
	if (!user) throw new BizError('Sign in required', 401);
	c.set('user', user);
	const admin = user.email === c.env.admin;
	if (adminOnly && !admin) throw new BizError('Forbidden', 403);
	if (!admin && permissions.has(route)) {
		const perms = await permService.userPermKeys(c, user.userId);
		if (!perms.includes(permissions.get(route))) throw new BizError('Forbidden', 403);
	}
	if (!await limit(c, 'API_LIMIT', String(user.userId))) throw new BizError('Try again later', 429);
	if ((route === 'POST /email/send' || route === 'PUT /my/resetPassword' || route === 'POST /user/add' || route === 'PUT /user/setPwd') &&
		!await limit(c, 'LOGIN_LIMIT', route + ':' + user.userId)) throw new BizError('Try again later', 429);
	return next();
});

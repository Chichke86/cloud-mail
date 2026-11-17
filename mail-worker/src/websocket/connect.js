import app from '../hono/hono';
import { ALL_EMAIL_HUB } from './notify';
import { canWatchAllEmail } from './auth';

app.get('/realtime', async (c) => {
	if (c.req.header('Upgrade')?.toLowerCase() !== 'websocket') return c.text('Upgrade required', 426);
	if (c.req.header('Origin') !== new URL(c.req.url).origin) return c.text('Forbidden', 403);
	if (!c.env.ws) return c.text('Unavailable', 503);
	const scope = c.req.query('scope') || 'inbox';
	const user = c.get('user');
	if (scope !== 'inbox' && scope !== ALL_EMAIL_HUB) return c.text('Invalid scope', 400);
	if (scope === ALL_EMAIL_HUB && !await canWatchAllEmail(c.env, user)) return c.text('Forbidden', 403);

	const hub = c.env.ws.getByName(scope === ALL_EMAIL_HUB ? scope : String(user.userId));
	// Forward only metadata generated after authentication. Never forward browser credentials.
	return hub.fetch('https://mail-ws/connect', {
		headers: { Upgrade: 'websocket', 'X-Session-Hash': c.get('sessionHash'), 'X-Scope': scope },
	});
});

import { Hono } from 'hono';
const app = new Hono();

import result from '../model/result';
import { bodyLimit } from 'hono/body-limit';

const tooLarge = (c) => c.json(result.fail('Request too large', 413), 413);
app.use('/login', bodyLimit({ maxSize: 8192, onError: tooLarge }));
app.use('/email/send', bodyLimit({ maxSize: 16 * 1024 * 1024, onError: tooLarge }));

app.onError((err, c) => {
	if (err.name === 'BizError') {
		return c.json(result.fail(err.message, err.code), [401, 403, 429].includes(err.code) ? err.code : 200);
	}
	console.error(JSON.stringify({ event: 'api_error', kind: err.name }));
	return c.json(result.fail('Internal server error', 500), 500);
});

export default app;



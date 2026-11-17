import production from '../src/index';
import bootstrap from '../src/bootstrap-local';
export { MailHub } from '../src/index';
export default {
	...production,
	fetch(request, env, ctx) {
		return new URL(request.url).pathname === '/bootstrap'
			? bootstrap.fetch(request, env)
			: production.fetch(request, env, ctx);
	},
};

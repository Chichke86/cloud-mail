import kvObjService from './kv-obj-service';

const r2Service = {
	async storageType(c) {
		return c.env.r2 ? 'R2' : 'KV';
	},

	async putObj(c, key, content, metadata) {
		if (!c.env.r2) return kvObjService.putObj(c, key, content, metadata);
		await c.env.r2.put(key, content, { httpMetadata: metadata });
	},

	async getObj(c, key) {
		return c.env.r2 ? c.env.r2.get(key) : kvObjService.getObj(c, key);
	},

	async toObjResp(c, key) {
		const obj = await this.getObj(c, key);
		return c.env.r2 && obj ? new Response(obj.body) : obj;
	},

	async delete(c, key) {
		return c.env.r2 ? c.env.r2.delete(key) : kvObjService.deleteObj(c, key);
	},
};
export default r2Service;

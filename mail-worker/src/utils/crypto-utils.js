import { scrypt, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';

const version = 'scrypt-v1:';
const options = { N: 32768, r: 8, p: 3, maxmem: 40 * 1024 * 1024 };
const validPassword = (value) => typeof value === 'string' && value.length > 0 &&
	new TextEncoder().encode(value).length <= 1024;
const digest = (password, salt) => new Promise((resolve, reject) => {
	scrypt(password, Buffer.from(salt, 'base64'), 32, options,
		(error, key) => error ? reject(error) : resolve(key));
});

const cryptoUtils = {
	validPassword,

	async hashPassword(password) {
		if (!validPassword(password)) throw new TypeError('Invalid password length');
		const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64');
		return { salt, hash: version + (await digest(password, salt)).toString('base64') };
	},

	async verifyPassword(password, salt, hash) {
		// Legacy hashes must be reset through the admin path; never authenticate SHA-256.
		if (!validPassword(password) || typeof salt !== 'string' ||
			!/^[A-Za-z0-9+/]{22}==$/.test(salt) || typeof hash !== 'string' ||
			!hash.startsWith(version)) return false;
		const stored = hash.slice(version.length);
		if (!/^[A-Za-z0-9+/]{43}=$/.test(stored)) return false;
		return timingSafeEqual(await digest(password, salt), Buffer.from(stored, 'base64'));
	},

	genRandomPwd() {
		return Buffer.from(crypto.getRandomValues(new Uint8Array(18))).toString('base64url');
	}
};

export default cryptoUtils;

import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from './config';

export const siteGateEnabled = (): boolean => !!config.sitePassphrase;

const KEYLEN = 32;
const N = 16384;

export const hashPassphrase = (passphrase: string): string => {
	const salt = randomBytes(16);
	const hash = scryptSync(passphrase, salt, KEYLEN, { N, r: 8, p: 1 });
	return `scrypt$${N}$${salt.toString('hex')}$${hash.toString('hex')}`;
};

export const verifyPassphrase = (passphrase: string, stored: string): boolean => {
	const [scheme, nStr, saltHex, hashHex] = stored.split('$');
	if (scheme !== 'scrypt') return false;
	const hash = scryptSync(passphrase, Buffer.from(saltHex, 'hex'), KEYLEN, {
		N: Number(nStr),
		r: 8,
		p: 1
	});
	return timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
};

/** Site gate: derived from env, verified per request.
 *  ponytail: direct scrypt per check, kv cache only if this shows up in profiles. */
export const verifySiteGate = (passphrase: string): boolean =>
	!!config.sitePassphrase && verifyPassphrase(passphrase, hashPassphrase(config.sitePassphrase));

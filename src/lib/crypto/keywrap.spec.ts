import { describe, expect, it } from 'vitest';
import {
	derivePasskey,
	exportContentKey,
	importContentKey,
	unwrapKeyWithDerived,
	wrapKeyWithDerived
} from './keywrap';
import { accountKeyFromPrfSecret, unwrapWithAccountKey, wrapWithAccountKey } from './prf';
import { encryptBytes, decryptBytes } from './format';
import { random } from './encode';

describe('passphrase wrap', () => {
	it('wraps and unwraps content key via derived passphrase key', async () => {
		const salt = random(16);
		const contentKey = await importContentKey(random(32));
		const wrapKey = await derivePasskey('correct horse', salt);
		const blob = await wrapKeyWithDerived(contentKey, wrapKey);
		const restored = await unwrapKeyWithDerived(blob, await derivePasskey('correct horse', salt));
		expect(await exportContentKey(restored)).toEqual(await exportContentKey(contentKey));
	});

	it('rejects wrong passphrase', async () => {
		const salt = random(16);
		const contentKey = await importContentKey(random(32));
		const blob = await wrapKeyWithDerived(contentKey, await derivePasskey('correct horse', salt));
		await expect(unwrapKeyWithDerived(blob, await derivePasskey('wrong', salt))).rejects.toThrow();
	});
});

describe('content round trip with wrapped key', () => {
	it('encrypt-recipients flow uses unwrapped key to decrypt', async () => {
		const salt = random(16);
		const keyRaw = random(32);
		const key = await importContentKey(keyRaw);
		const wrapKey = await derivePasskey('pw', salt);
		const wrapped = await wrapKeyWithDerived(key, wrapKey);
		const cipher = await encryptBytes(new TextEncoder().encode('hello zeropaste'), key);
		const restored = await unwrapKeyWithDerived(wrapped, await derivePasskey('pw', salt));
		const plain = await decryptBytes(cipher, restored);
		expect(new TextDecoder().decode(plain)).toBe('hello zeropaste');
	});
});

describe('account key prf wrap', () => {
	it('wraps and unwraps content key with account key', async () => {
		const prfSecret = random(32);
		const accountKey = await accountKeyFromPrfSecret(prfSecret);
		const keyRaw = random(32);
		const wrapped = await wrapWithAccountKey(accountKey, keyRaw);
		const sameAccount = await accountKeyFromPrfSecret(prfSecret);
		expect(await unwrapWithAccountKey(sameAccount, wrapped)).toEqual(keyRaw);
	});

	it('rejects different prf secret', async () => {
		const accountKey = await accountKeyFromPrfSecret(random(32));
		const wrapped = await wrapWithAccountKey(accountKey, random(32));
		await expect(
			unwrapWithAccountKey(await accountKeyFromPrfSecret(random(32)), wrapped)
		).rejects.toThrow();
	});
});

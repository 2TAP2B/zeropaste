import { random } from './encode';

export const accountKeyFromPrfSecret = async (prfSecret: Uint8Array): Promise<CryptoKey> =>
	crypto.subtle.importKey('raw', prfSecret as unknown as BufferSource, 'AES-GCM', false, [
		'encrypt',
		'decrypt'
	]);

export const wrapWithAccountKey = async (
	accountKey: CryptoKey,
	contentKeyRaw: Uint8Array
): Promise<Uint8Array> => {
	const iv = random(12);
	const wrapped = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv: iv as unknown as BufferSource },
			accountKey,
			contentKeyRaw as unknown as BufferSource
		)
	);
	return new Uint8Array([...iv, ...wrapped]);
};

export const unwrapWithAccountKey = async (
	accountKey: CryptoKey,
	blob: Uint8Array
): Promise<Uint8Array> =>
	new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: blob.slice(0, 12) as unknown as BufferSource },
			accountKey,
			blob.slice(12) as unknown as BufferSource
		)
	);

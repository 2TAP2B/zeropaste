const ITERATIONS = 600_000;

export const importContentKey = async (raw: Uint8Array): Promise<CryptoKey> =>
	crypto.subtle.importKey('raw', raw as unknown as BufferSource, 'AES-GCM', true, [
		'encrypt',
		'decrypt'
	]);

export const exportContentKey = async (key: CryptoKey): Promise<Uint8Array> =>
	new Uint8Array(await crypto.subtle.exportKey('raw', key));

export const derivePasskey = async (passphrase: string, salt: Uint8Array): Promise<CryptoKey> => {
	const base = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(passphrase) as unknown as BufferSource,
		'PBKDF2',
		false,
		['deriveKey']
	);
	return crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt as unknown as BufferSource,
			iterations: ITERATIONS,
			hash: 'SHA-256'
		},
		base,
		{ name: 'AES-GCM', length: 256 },
		true,
		['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
	);
};

export const wrapKeyWithDerived = async (
	contentKey: CryptoKey,
	passphraseKey: CryptoKey
): Promise<Uint8Array> => {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const raw = await exportContentKey(contentKey);
	const wrapped = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv: iv as unknown as BufferSource },
			passphraseKey,
			raw as unknown as BufferSource
		)
	);
	return new Uint8Array([...iv, ...wrapped]);
};

export const unwrapKeyWithDerived = async (
	blob: Uint8Array,
	passphraseKey: CryptoKey
): Promise<CryptoKey> => {
	const iv = blob.slice(0, 12);
	const raw = new Uint8Array(
		await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: iv as unknown as BufferSource },
			passphraseKey,
			blob.slice(12) as unknown as BufferSource
		)
	);
	return importContentKey(raw);
};

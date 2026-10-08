import {
	importContentKey,
	derivePasskey,
	wrapKeyWithDerived,
	exportContentKey,
	unwrapKeyWithDerived
} from '#lib/crypto/keywrap';
import { encryptChunked, decryptChunked } from '#lib/crypto/format';
import { b64urlEncode, b64urlDecode, random } from '#lib/crypto/encode';

const PBKDF2_SLICES = 600_000;

export interface ShareKeys {
	/** value for the URL fragment (#k=...) */
	fragment: string;
	contentKey: CryptoKey;
}

export async function makeShareKeys(passphrase: string | null): Promise<ShareKeys> {
	const raw = random(32);
	const contentKey = await importContentKey(raw);
	if (!passphrase) return { fragment: b64urlEncode(raw), contentKey };
	const ksalt = random(16);
	const wrapKey = await derivePasskey(passphrase, ksalt);
	const wrapped = await wrapKeyWithDerived(contentKey, wrapKey);
	return {
		fragment: `P2.${b64urlEncode(ksalt)}.${b64urlEncode(wrapped)}`,
		contentKey
	};
}

export async function contentKeyFromFragment(
	fragment: string,
	passphrase: string | null
): Promise<CryptoKey> {
	if (!fragment.startsWith('P2.')) return importContentKey(b64urlDecode(fragment));
	const [, ksaltB64, wrappedB64] = fragment.split('.');
	if (!passphrase) throw new Error('passphrase required');
	const wrapKey = await derivePasskey(passphrase, b64urlDecode(ksaltB64));
	return unwrapKeyWithDerived(b64urlDecode(wrappedB64), wrapKey);
}

/** separate domain from content keys: what the server compares for passphrase shares */
export async function passProof(passphrase: string, srvSalt: string): Promise<string> {
	const base = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(passphrase) as unknown as BufferSource,
		'PBKDF2',
		false,
		['deriveBits']
	);
	const srvSaltBytes = b64urlDecode(srvSalt);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: srvSaltBytes as unknown as BufferSource,
			iterations: PBKDF2_SLICES,
			hash: 'SHA-256'
		},
		base,
		256
	);
	return b64urlEncode(new Uint8Array(bits));
}

export const passProofSalt = (): string => b64urlEncode(random(16));

export async function encryptFileToRequest(file: File, contentKey: CryptoKey): Promise<BodyInit> {
	return wrappedStream(
		encryptChunked(file.stream() as AsyncIterable<Uint8Array>, contentKey, file.size)
	);
}

export async function encryptTextToRequest(text: string, contentKey: CryptoKey): Promise<BodyInit> {
	const plain = new TextEncoder().encode(text);
	const encrypted = encryptChunked([plain], contentKey, plain.length);
	return wrappedStream(encrypted);
}

export function wrappedStream(gen: AsyncGenerator<Uint8Array>): ReadableStream<Uint8Array> {
	return new ReadableStream<Uint8Array>({
		async pull(controller) {
			const { done, value } = await gen.next();
			if (done) controller.close();
			else controller.enqueue(value);
		}
	});
}

export async function decryptFetched(
	response: Response,
	contentKey: CryptoKey
): Promise<Uint8Array> {
	if (!response.ok) throw new Error(`content fetch failed: ${response.status}`);
	if (!response.body) throw new Error('no body');
	const plain = wrappedStream(decryptChunked(response.body, contentKey));
	return new Uint8Array(await new Response(plain).arrayBuffer());
}

export const saveBlob = (data: Uint8Array, name: string): void => {
	const blob = new Blob([data as unknown as BlobPart], { type: 'application/octet-stream' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = name;
	a.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export const exportedKey = exportContentKey;

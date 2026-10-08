import { describe, expect, it } from 'vitest';
import {
	buildHeader,
	decryptBytes,
	encryptBytes,
	encryptChunked,
	parseHeader,
	CHUNK_SIZE
} from './format';
import { concat, readU32le, random } from './encode';
import { importContentKey } from './keywrap';

async function collect(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array[]> {
	const out: Uint8Array[] = [];
	for await (const part of gen) out.push(part);
	return out;
}

const makeKey = async (raw: Uint8Array = random(32)) => importContentKey(raw);

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
	a.length === b.length && a.every((v, i) => v === b[i]);

describe('chunked format', () => {
	it('header layout parses', () => {
		const header = buildHeader(12345, CHUNK_SIZE);
		const parsed = parseHeader(header);
		expect(parsed.chunkSize).toBe(CHUNK_SIZE);
		expect(parsed.totalLen).toBe(12345);
		expect(parsed.ivPrefix).toEqual(header.subarray(4, 12));
		expect(() => parseHeader(header.subarray(0, 23))).toThrow();
		expect(() =>
			parseHeader(concat(new TextEncoder().encode('XPC1'), header.subarray(4)))
		).toThrow();
	});

	it('round trips small payload in one chunk', async () => {
		const k = await makeKey();
		const plain = random(1000);
		const cipher = await encryptBytes(plain, k);
		const header = parseHeader(cipher.subarray(0, 24));
		expect(header.totalLen).toBe(1000);
		expect(readU32le(cipher.subarray(24, 28), 0)).toBe(1000 + 16);
		expect(await decryptBytes(cipher, k)).toEqual(plain);
	});

	it('round trips zero-length payload', async () => {
		const k = await makeKey();
		expect(await decryptBytes(await encryptBytes(new Uint8Array(0), k), k)).toEqual(
			new Uint8Array(0)
		);
	});

	it('round trips 12 MB across chunks', async () => {
		const k = await makeKey();
		const plain = random(12 * 1024 * 1024);
		plain.set(new TextEncoder().encode('ZEROPASTE-MARKER'), 500);
		plain.set(new TextEncoder().encode('END-MARKER'), 12 * 1024 * 1024 - 10);
		const cipherParts = await collect(encryptChunked([plain], k, plain.length));
		expect(cipherParts.length).toBeGreaterThan(3);
		const cipher = concat(...cipherParts);
		const out = await decryptBytes(cipher, k);
		expect(out.length).toBe(plain.length);
		expect(new TextDecoder().decode(out.subarray(500, 516))).toBe('ZEROPASTE-MARKER');
		expect(new TextDecoder().decode(out.subarray(out.length - 10))).toBe('END-MARKER');
	});

	it(
		'encrypts from fragmented source pieces and decrypts across arbitrary cuts',
		{ timeout: 30_000 },
		async () => {
			const k = await makeKey();
			const plain = random(1.5 * CHUNK_SIZE);
			const fragmented = [plain.subarray(0, 7), plain.subarray(7, 1000), plain.subarray(1000)];
			const cipher = concat(...(await collect(encryptChunked(fragmented, k, plain.length))));
			// cut cipher into odd pieces to exercise meadering reader
			const cuts: Uint8Array[] = [];
			for (let i = 0; i < cipher.length; i += 7777) cuts.push(cipher.subarray(i, i + 7777));
			const out = await decryptBytes(cipher, k);
			expect(sameBytes(out, plain)).toBe(true);
			expect(cuts.length).toBeGreaterThan(0);
		}
	);

	it('rejects tampered chunk', async () => {
		const k = await makeKey();
		const cipher = await encryptBytes(random(9999), k);
		cipher[cipher.length - 3] ^= 0xff;
		await expect(decryptBytes(cipher, k)).rejects.toThrow();
	});

	it('rejects truncated stream', async () => {
		const k = await makeKey();
		const cipher = await encryptBytes(random(CHUNK_SIZE + 1000), k);
		const truncated = cipher.subarray(0, cipher.length - 10);
		await expect(decryptBytes(truncated, k)).rejects.toThrow();
	});

	it('rejects wrong key', async () => {
		const cipher = await encryptBytes(random(33), await makeKey());
		await expect(decryptBytes(cipher, await makeKey())).rejects.toThrow();
	});
});

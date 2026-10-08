import { concat, readU32le, readU64le, u32le, u64le, random } from './encode';

const MAGIC = new TextEncoder().encode('ZPC1');
const HEADER_LEN = 24;
const TAG_LEN = 16;
export const CHUNK_SIZE = 5 * 1024 * 1024;

export interface Header {
	ivPrefix: Uint8Array;
	chunkSize: number;
	totalLen: number;
}

export const buildHeader = (totalLen: number, chunkSize = CHUNK_SIZE): Uint8Array =>
	concat(MAGIC, random(8), u32le(chunkSize), u64le(totalLen));

export const parseHeader = (header: Uint8Array): Header => {
	if (header.length !== HEADER_LEN) throw new Error('bad header length');
	if (!header.subarray(0, 4).every((b, i) => b === MAGIC[i]))
		throw new Error('not a zeropaste blob');
	const chunkSize = readU32le(header, 12);
	if (chunkSize === 0) throw new Error('bad chunk size');
	return { ivPrefix: header.subarray(4, 12), chunkSize, totalLen: readU64le(header, 16) };
};

const ivFor = (prefix: Uint8Array, index: number): Uint8Array => {
	const iv = new Uint8Array(12);
	iv.set(prefix, 0);
	new DataView(iv.buffer).setUint32(8, index >>> 0, false);
	return iv;
};

const encryptChunk = async (
	key: CryptoKey,
	header: Uint8Array,
	iv: Uint8Array,
	plain: Uint8Array
): Promise<Uint8Array> =>
	new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: iv as unknown as BufferSource,
				additionalData: header as unknown as BufferSource
			},
			key,
			plain as unknown as BufferSource
		)
	);

const decryptChunk = async (
	key: CryptoKey,
	header: Uint8Array,
	iv: Uint8Array,
	cipher: Uint8Array
): Promise<Uint8Array> =>
	new Uint8Array(
		await crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv: iv as unknown as BufferSource,
				additionalData: header as unknown as BufferSource
			},
			key,
			cipher as unknown as BufferSource
		)
	);

export async function* encryptChunked(
	source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
	key: CryptoKey,
	totalLen: number,
	chunkSize = CHUNK_SIZE
): AsyncGenerator<Uint8Array> {
	const header = buildHeader(totalLen, chunkSize);
	yield header;
	const { ivPrefix, chunkSize: size } = parseHeader(header);
	let index = 0;
	const buffered = new Uint8Array(size);
	let bufferedLen = 0;
	for await (const piece of source) {
		let offset = 0;
		while (offset < piece.length) {
			const take = Math.min(size - bufferedLen, piece.length - offset);
			buffered.set(piece.subarray(offset, offset + take), bufferedLen);
			bufferedLen += take;
			offset += take;
			if (bufferedLen === size) {
				const cipher = await encryptChunk(key, header, ivFor(ivPrefix, index++), buffered);
				yield u32le(cipher.length);
				yield cipher;
				bufferedLen = 0;
			}
		}
	}
	if (bufferedLen > 0) {
		const cipher = await encryptChunk(
			key,
			header,
			ivFor(ivPrefix, index++),
			buffered.subarray(0, bufferedLen)
		);
		yield u32le(cipher.length);
		yield cipher;
	}
	if (totalLen === 0 ? index !== 0 : index * size - size + bufferedLen !== totalLen) {
		throw new Error('source does not match declared totalLen');
	}
}

export async function* decryptChunked(
	source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
	key: CryptoKey
): AsyncGenerator<Uint8Array> {
	const reader = new ByteReader(source as AsyncIterable<Uint8Array>);
	const header = await reader.exact(HEADER_LEN);
	const { ivPrefix, chunkSize, totalLen } = parseHeader(header);
	let index = 0;
	let emitted = 0;
	for (;;) {
		let frame: Uint8Array;
		try {
			frame = await reader.exact(4);
		} catch {
			break;
		}
		const cipherLen = readU32le(frame, 0);
		if (cipherLen < TAG_LEN || cipherLen > chunkSize + TAG_LEN) throw new Error('bad frame length');
		const cipher = await reader.exact(cipherLen);
		const plain = await decryptChunk(key, header, ivFor(ivPrefix, index++), cipher);
		emitted += plain.length;
		yield plain;
	}
	if (emitted !== totalLen) throw new Error('length mismatch after decrypt');
}

export const encryptBytes = async (
	plain: Uint8Array,
	key: CryptoKey,
	chunkSize = CHUNK_SIZE
): Promise<Uint8Array> =>
	concat(...(await collect(encryptChunked([plain], key, plain.length, chunkSize))));

export const decryptBytes = async (cipher: Uint8Array, key: CryptoKey): Promise<Uint8Array> =>
	concat(...(await collect(decryptChunked([cipher], key))));

async function collect(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array[]> {
	const parts: Uint8Array[] = [];
	for await (const part of gen) parts.push(part);
	return parts;
}

class ByteReader {
	private queue: Uint8Array[] = [];
	private queueLen = 0;
	private done = false;

	constructor(private source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>) {}

	private iterator?: Iterator<Uint8Array>;
	private asyncIterator?: AsyncIterator<Uint8Array>;

	private async pull(): Promise<boolean> {
		if (this.done) return false;
		const source = this.source as AsyncIterable<Uint8Array> & Iterable<Uint8Array>;
		if (typeof source[Symbol.asyncIterator] === 'function') {
			this.asyncIterator ??= (source as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
			const chunk = await this.asyncIterator.next();
			if (chunk.done) {
				this.done = true;
				return false;
			}
			this.queue.push(chunk.value);
			this.queueLen += chunk.value.length;
			return true;
		}
		if (typeof source[Symbol.iterator] === 'function') {
			this.iterator ??= source[Symbol.iterator]();
			const next = this.iterator.next();
			if (next.done) {
				this.done = true;
				return false;
			}
			this.queue.push(next.value);
			this.queueLen += next.value.length;
			return true;
		}
		throw new Error('unreadable source');
	}

	async exact(n: number): Promise<Uint8Array> {
		while (this.queueLen < n) {
			if (!(await this.pull())) throw new Error('stream truncated');
		}
		if (this.queueLen === n && this.queue.length === 1 && this.queue[0].length === n) {
			const out = this.queue[0];
			this.queue = [];
			this.queueLen = 0;
			return out;
		}
		const out = new Uint8Array(n);
		let needed = n;
		let filled = 0;
		while (needed > 0) {
			const head = this.queue[0];
			const take = Math.min(head.length, needed);
			out.set(head.subarray(0, take), filled);
			filled += take;
			needed -= take;
			if (take === head.length) {
				this.queue.shift();
			} else {
				this.queue[0] = head.subarray(take);
			}
			this.queueLen -= take;
		}
		return out;
	}
}

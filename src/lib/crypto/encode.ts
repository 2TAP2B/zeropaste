export const b64urlEncode = (data: Uint8Array): string => {
	let bin = '';
	for (const byte of data) bin += String.fromCharCode(byte);
	return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
};

export const b64urlDecode = (text: string): Uint8Array => {
	let b64 = text.replaceAll('-', '+').replaceAll('_', '/');
	b64 += '='.repeat((4 - (b64.length % 4)) % 4);
	const bin = atob(b64);
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

export const random = (length: number): Uint8Array => {
	const out = new Uint8Array(length);
	for (let i = 0; i < length; i += 65536) {
		crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, length)));
	}
	return out;
};

export const concat = (...parts: Uint8Array[]): Uint8Array => {
	const total = parts.reduce((sum, part) => sum + part.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
};

export const u32le = (value: number): Uint8Array => {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, value, true);
	return out;
};

export const u64le = (value: number): Uint8Array => {
	const out = new Uint8Array(8);
	new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
	return out;
};

export const readU32le = (data: Uint8Array, offset = 0): number =>
	new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, true);

export const readU64le = (data: Uint8Array, offset = 0): number =>
	Number(new DataView(data.buffer, data.byteOffset + offset, 8).getBigUint64(0, true));

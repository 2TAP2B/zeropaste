import { describe, expect, it } from 'vitest';
import { b64urlDecode, b64urlEncode, random } from './encode';

describe('b64url', () => {
	it('round trips binary data', () => {
		for (const len of [0, 1, 3, 4, 5, 16, 32, 100]) {
			const data = random(len);
			expect(b64urlDecode(b64urlEncode(data))).toEqual(data);
		}
	});

	it('is url safe and canonical', () => {
		expect(b64urlEncode(b64urlDecode('a-b_'))).toBe('a-b_');
	});
});

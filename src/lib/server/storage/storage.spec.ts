import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { diskStorage } from './disk';
import type { StorageContext } from './types';

const runSuite = (name: string, make: () => StorageContext) => {
	describe(name, () => {
		let storage: StorageContext;
		let key: string;

		beforeEach(() => {
			storage = make();
			key = `t/${randomUUID()}.bin`;
		});

		afterEach(() => storage.delete([key]));

		it('round trips bytes', async () => {
			const data = new Uint8Array([1, 2, 3, 250, 255]);
			await storage.put(
				key,
				new Response(data as unknown as BodyInit).body as ReadableStream<Uint8Array>
			);
			expect(await storage.exists(key)).toBe(true);
			const back = await storage.get(key);
			const bytes = new Uint8Array(await new Response(back).arrayBuffer());
			expect(bytes).toEqual(data);
			expect(await storage.sizeOf(key)).toBe(5);
		});

		it('exists=false for unknown key; delete idempotent', async () => {
			expect(await storage.exists(key)).toBe(false);
			await storage.delete([key]);
			expect(await storage.exists(key)).toBe(false);
		});
	});
};

const root = `/tmp/zp-storage-test-${process.pid}`;

runSuite('disk storage', () => diskStorage(root));

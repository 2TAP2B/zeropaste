import { createReadStream, createWriteStream, mkdirSync } from 'node:fs';
import { mkdir, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import type { StorageContext } from './types';

export const diskStorage = (root: string): StorageContext => {
	mkdirSync(root, { recursive: true });
	const path = (key: string) => join(root, key);
	return {
		kind: 'disk',
		plan: async () => ({ kind: 'direct' as const }),
		async put(key, stream) {
			await mkdir(dirname(path(key)), { recursive: true });
			const out = createWriteStream(path(key));
			const reader = stream.getReader();
			for (;;) {
				const { done, value } = await reader.read();
				if (done) break;
				if (!out.write(value)) {
					await new Promise<void>((resolve, reject) => {
						out.once('drain', resolve);
						out.once('error', reject);
					});
				}
			}
			await new Promise<void>((resolve, reject) => {
				out.end(() => resolve());
				out.on('error', reject);
			});
		},
		async get(key) {
			await stat(path(key));
			return Readable.toWeb(createReadStream(path(key))) as ReadableStream<Uint8Array>;
		},
		async sizeOf(key) {
			return (await stat(path(key))).size;
		},
		async delete(keys) {
			const { rm } = await import('node:fs/promises');
			for (const key of keys) await rm(path(key), { force: true });
		},
		async exists(key) {
			try {
				await stat(path(key));
				return true;
			} catch {
				return false;
			}
		}
	};
};

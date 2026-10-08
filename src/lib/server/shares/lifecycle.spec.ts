import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	attachFilesToReverse,
	consumeShare,
	createShare,
	createReverseShare,
	deleteReverseShare,
	deleteShare,
	getReverseByLsug,
	getShareBySlug,
	getShareHumanState,
	listReverseByOwner,
	listSharesForOwner,
	purge
} from './index';
import { openDb, closeDb, getDb } from '../db';
import { diskStorage } from '../storage/disk';
import { encryptBytes } from '../../crypto/format';
import { importContentKey } from '../../crypto/keywrap';

const dataDir = mkdtempSync(join(tmpdir(), 'zp-life-'));
const storage = diskStorage(dataDir);

beforeAll(() => {
	openDb(join(dataDir, 'test.db'));
});

afterAll(() => {
	closeDb();
	rmSync(dataDir, { recursive: true, force: true });
});

const meta = (size = 16) => ({ name: 'a.txt', mime: 'text/plain', size });

describe('share lifecycle', () => {
	it('create → active → burn → purge removes blobs', async () => {
		const { share, files } = await createShare({
			kind: 'files',
			files: [meta()],
			burn: true,
			expiresInSecs: 3600
		});
		expect(getShareBySlug(share.slug)).toBeTruthy();
		expect(getShareHumanState(share.id).status).toBe('available');

		const key = await importContentKey(new Uint8Array(32));
		const cipher = await encryptBytes(new Uint8Array([9]), key);
		const file = files[0];
		await storage.put(file.blob, new Response(cipher as unknown as BodyInit).body!);
		expect(existsSync(join(dataDir, file.blob))).toBe(true);

		const first = consumeShare(share.slug);
		expect(first).toEqual({ ok: true });
		expect(getShareHumanState(share.id).status).toBe('burned');
		// second consumer rejected (already consumed)
		expect(await consumeShare(share.slug)).toEqual({ ok: false, reason: 'already' });

		await purge();
		expect(getShareBySlug(share.slug)).toBeNull();
	});

	it('unknown slug → gone', () => {
		expect(consumeShare('nope-worm-99')).toEqual({ ok: false, reason: 'gone' });
	});

	it('expired share purges without download', async () => {
		const { share } = await createShare({
			kind: 'paste',
			files: [meta()],
			burn: false,
			expiresInSecs: -1
		});
		expect(getShareHumanState(share.id).status).toBe('expired');
		expect(consumeShare(share.slug)).toEqual({ ok: false, reason: 'gone' });
		await purge();
		expect(getShareBySlug(share.slug)).toBeNull();
	});

	it('non-burn share survives multiple downloads until expiry', async () => {
		const { share } = await createShare({
			kind: 'files',
			files: [meta()],
			burn: false,
			expiresInSecs: 3600
		});
		expect(consumeShare(share.slug)).toEqual({ ok: true });
		expect(consumeShare(share.slug)).toEqual({ ok: true });
		expect(getShareHumanState(share.id).status).toBe('available');
	});

	it('unbounded slug uniqueness retry works', async () => {
		const shares = await Promise.all(
			Array.from({ length: 25 }, () =>
				createShare({ kind: 'files', files: [meta()], burn: false, expiresInSecs: 3600 })
			)
		);
		const slugs = new Set(shares.map((s) => s.share.slug));
		expect(slugs.size).toBe(25);
	});
});

const ensureAccount = (id: string) =>
	getDb()
		.prepare('INSERT OR IGNORE INTO accounts (id, created_at) VALUES (?, ?)')
		.run(id, Date.now());

describe('reverse shares', () => {
	it('creates with custom lsug, rejects bad ones, lists for owner', async () => {
		ensureAccount('acct-1');
		const { reverseId } = createReverseShare({
			lsug: 'best-friend',
			account: 'acct-1',
			expiresInSecs: 3600
		});
		expect(getReverseByLsug('best-friend')?.id).toBe(reverseId);
		expect(getReverseByLsug('Best Friend!')).toBeNull();

		await attachFilesToReverse(reverseId, [meta(42)]);
		const owned = listReverseByOwner('acct-1') as { lsug: string; file_count: number }[];
		expect(owned[0].lsug).toBe('best-friend');
		expect(owned[0].file_count).toBe(1);

		await deleteReverseShare(reverseId);
		expect(getReverseByLsug('best-friend')).toBeNull();
	});

	it('expired reverse share invisible', async () => {
		ensureAccount('acct-2');
		const { lsug } = createReverseShare({ account: 'acct-2', expiresInSecs: -1 });
		expect(getReverseByLsug(lsug)).toBeNull();
	});
});

describe('dashboard listings', () => {
	it('lists created shares with totals', async () => {
		const { share } = await createShare({
			kind: 'files',
			files: [meta(100), meta(200)],
			burn: false,
			expiresInSecs: 3600,
			accountId: 'acct-9'
		});
		const rows = listSharesForOwner('acct-9');
		expect(rows.map((r) => r.id)).toContain(share.id);
		const found = rows.find((r) => r.id === share.id)!;
		expect(found.file_count).toBe(2);
		expect(found.total_size).toBe(300);
		deleteShare(share.id);
		expect(getShareBySlug(share.slug)).toBeNull();
		expect(listSharesForOwner('acct-9')).toHaveLength(0);
	});
});

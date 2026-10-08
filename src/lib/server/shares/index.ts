import { randomUUID, randomBytes } from 'node:crypto';
import { getDb } from '../db';
import { getStorage, type UploadPlan } from '../storage';
import { genSlug } from './slug';

export interface FileMeta {
	name: string;
	mime: string;
	size: number;
}

export interface NewShareInput {
	kind: 'files' | 'paste';
	files: FileMeta[];
	burn: boolean;
	expiresInSecs: number;
	passSalt?: string;
	passVerifier?: string;
	accountId?: string;
}

export interface ShareRow {
	id: string;
	kind: string;
	slug: string;
	created_at: number;
	expires_at: number;
	burn: number;
	consumed_at: number | null;
	owner_account_id: string | null;
	pass_salt: string | null;
	pass_verifier: string | null;
}

export interface FileRow {
	id: string;
	share_id: string | null;
	reverse_share_id: string | null;
	idx: number;
	name: string;
	mime: string;
	size: number;
	blob: string;
	created_at: number;
}

const insertShare = `
INSERT INTO shares (id, kind, slug, created_at, expires_at, burn, owner_account_id, pass_salt, pass_verifier)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
const insertFile = `
INSERT INTO files (id, share_id, reverse_share_id, idx, name, mime, size, blob, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

const now = () => Date.now();

export async function createShare(input: NewShareInput): Promise<{
	share: ShareRow;
	files: (FileRow & { upload: UploadPlan })[];
}> {
	const db = getDb();
	const storage = getStorage();
	const id = randomUUID();
	const slug = genSlug();
	const t = now();
	let slugFinal = slug;
	for (let attempt = 0; attempt < 10; attempt++) {
		try {
			db.prepare(insertShare).run(
				id,
				input.kind,
				slugFinal,
				t,
				t + input.expiresInSecs * 1000,
				input.burn ? 1 : 0,
				input.accountId ?? null,
				input.passSalt ?? null,
				input.passVerifier ?? null
			);
			break;
		} catch (err) {
			if (attempt === 9) throw err;
			slugFinal = genSlug();
		}
	}
	const files = await Promise.all(
		input.files.map(async (meta, idx) => {
			const file = createFileRow(id, null, idx, meta);
			db.prepare(insertFile).run(
				file.id,
				id,
				null,
				idx,
				file.name,
				file.mime,
				file.size,
				file.blob,
				t
			);
			return { ...file, upload: await storage.plan(file.blob, file.size) };
		})
	);
	const share = getShareRow(id);
	if (!share) throw new Error('share vanished');
	return { share, files };
}

function createFileRow(
	shareId: string | null,
	reverseId: string | null,
	idx: number,
	meta: FileMeta
): FileRow {
	return {
		id: randomUUID(),
		share_id: shareId,
		reverse_share_id: reverseId,
		idx,
		name: meta.name,
		mime: meta.mime,
		size: meta.size,
		blob: `${randomBytes(16).toString('hex')}.zpc`,
		created_at: now()
	};
}

/** Marks the share consumed (burn-after-read) at the start of a download session.
 *  Returns true on a fresh burn (this bowser session initiated the burn). */
export function consumeShare(
	slug: string
): { ok: boolean; reason: 'gone' | 'already' } | { ok: true } {
	const db = getDb();
	const share = getShareBySlug(slug);
	if (!share) return { ok: false, reason: 'gone' };
	if (share.expires_at <= now()) return { ok: false, reason: 'gone' };
	if (!share.burn) return { ok: true };
	const res = db
		.prepare('UPDATE shares SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL')
		.run(now(), share.id);
	if (res.changes === 0) return { ok: false, reason: 'already' };
	return { ok: true };
}

export function filesForShare(shareId: string): FileRow[] {
	return getDb()
		.prepare('SELECT * FROM files WHERE share_id = ? ORDER BY idx')
		.all(shareId) as FileRow[];
}

export function fileForFileId(fileId: string): FileRow | null {
	const row = getDb().prepare('SELECT * FROM files WHERE id = ?').get(fileId) as FileRow | null;
	return row ?? null;
}

// reverse shares
export interface ReverseShareInput {
	lsug?: string;
	account: string;
	expiresInSecs: number;
	fileCount?: number;
}

export function createReverseShare(input: ReverseShareInput): {
	reverseId: string;
	lsug: string;
} {
	const db = getDb();
	const id = randomUUID();
	let lsug = input.lsug?.trim();
	if (!lsug) {
		lsug = `rv-${randomBytes(6).toString('hex')}`;
	}
	// validate custom lsug: lowercase alphanum + dash, 3..64
	if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(lsug)) throw new Error('bad lsug');
	const t = now();
	for (let attempt = 0; attempt < 10; attempt++) {
		try {
			db.prepare(
				'INSERT INTO reverse_shares (id, lsug, account_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
			).run(id, lsug, input.account, t, t + input.expiresInSecs * 1000);
			break;
		} catch (err) {
			if (attempt === 9) throw err;
			if (input.lsug) throw err; // custom slug conflicts: surface
			lsug = `rv-${randomBytes(6).toString('hex')}`;
		}
	}
	return { reverseId: id, lsug };
}

export function getReverseOwner(id: string): string | null {
	const row = getDb().prepare('SELECT account_id FROM reverse_shares WHERE id = ?').get(id) as
		{ account_id: string } | undefined;
	return row?.account_id ?? null;
}

export function getReverseById(
	id: string
): { id: string; lsug: string; expires_at: number } | null {
	const row = getDb()
		.prepare('SELECT id, lsug, expires_at FROM reverse_shares WHERE id = ?')
		.get(id) as { id: string; lsug: string; expires_at: number } | null;
	if (!row) return null;
	if (row.expires_at <= now()) return null;
	return row;
}

export function getReverseByLsug(
	lsug: string
): { id: string; lsug: string; expires_at: number } | null {
	const row = getDb()
		.prepare('SELECT id, lsug, expires_at FROM reverse_shares WHERE lsug = ?')
		.get(lsug) as { id: string; lsug: string; expires_at: number } | null;
	if (!row) return null;
	if (row.expires_at <= now()) return null;
	return row;
}

export function listReverseByOwner(account: string) {
	return getDb()
		.prepare(
			`SELECT rs.*, (SELECT COUNT(*) FROM files f WHERE f.reverse_share_id = rs.id) AS file_count
			 FROM reverse_shares rs WHERE rs.account_id = ? ORDER BY rs.created_at DESC`
		)
		.all(account);
}

export function filesForReverse(reverseId: string): FileRow[] {
	return getDb()
		.prepare('SELECT * FROM files WHERE reverse_share_id = ? ORDER BY idx')
		.all(reverseId) as FileRow[];
}

export function attachFilesToReverse(reverseId: string, files: FileMeta[]) {
	const db = getDb();
	const reverse = db.prepare('SELECT id FROM reverse_shares WHERE id = ?').get(reverseId);
	if (!reverse) throw new Error('no such reverse share');
	return Promise.all(
		files.map(async (meta, idx) => {
			const file = createFileRow(null, reverseId, idx, meta);
			db.prepare(insertFile).run(
				file.id,
				null,
				reverseId,
				idx,
				file.name,
				file.mime,
				file.size,
				file.blob,
				now()
			);
			return { ...file, upload: await getStorage().plan(file.blob, file.size) };
		})
	);
}

export function listSharesForOwner(
	account: string
): (ShareRow & { file_count: number; total_size: number })[] {
	return getDb()
		.prepare(
			`SELECT s.*, COUNT(f.id) AS file_count, COALESCE(SUM(f.size), 0) AS total_size
			 FROM shares s LEFT JOIN files f ON f.share_id = s.id
			 WHERE s.owner_account_id = ? GROUP BY s.id ORDER BY s.created_at DESC`
		)
		.all(account) as (ShareRow & { file_count: number; total_size: number })[];
}

export function deleteShare(id: string): void {
	const files = getDb().prepare('SELECT blob FROM files WHERE share_id = ?').all(id) as {
		blob: string;
	}[];
	getDb().prepare('DELETE FROM shares WHERE id = ?').run(id);
	void getStorage().delete(files.map((f) => f.blob));
}

export function deleteReverseShare(id: string): void {
	const db = getDb();
	const files = db.prepare('SELECT blob FROM files WHERE reverse_share_id = ?').all(id) as {
		blob: string;
	}[];
	db.prepare('DELETE FROM reverse_shares WHERE id = ?').run(id);
	if (files.length) void getStorage().delete(files.map((f) => f.blob));
}

/** Purge expired or consumed shares: delete blobs then tombstone rows. */
export async function purge(
	nowMs = now()
): Promise<{ shares: number; reverse: number; files: number }> {
	const db = getDb();
	const expiredShares = db
		.prepare('SELECT id FROM shares WHERE expires_at <= ? OR consumed_at IS NOT NULL')
		.all(nowMs) as { id: string }[];
	const expiredReverse = db
		.prepare('SELECT id FROM reverse_shares WHERE expires_at <= ?')
		.all(nowMs) as { id: string }[];

	let filesDeleted = 0;
	for (const { id } of expiredShares) {
		const files = db.prepare('SELECT blob FROM files WHERE share_id = ?').all(id) as {
			blob: string;
		}[];
		if (files.length) {
			await getStorage().delete(files.map((f) => f.blob));
			filesDeleted += files.length;
		}
	}
	for (const { id } of expiredReverse) {
		const files = db.prepare('SELECT blob FROM files WHERE reverse_share_id = ?').all(id) as {
			blob: string;
		}[];
		if (files.length) {
			await getStorage().delete(files.map((f) => f.blob));
			filesDeleted += files.length;
		}
	}
	db.prepare('DELETE FROM shares WHERE expires_at <= ? OR consumed_at IS NOT NULL').run(nowMs);
	db.prepare('DELETE FROM reverse_shares WHERE expires_at <= ?').run(nowMs);
	db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(nowMs);
	db.prepare('DELETE FROM challenges WHERE expires_at <= ?').run(nowMs);
	return { shares: expiredShares.length, reverse: expiredReverse.length, files: filesDeleted };
}

export const getShareHumanStateLocal = getShareHumanState;

export function getShareRow(id: string): ShareRow | null {
	const row = getDb().prepare('SELECT * FROM shares WHERE id = ?').get(id) as ShareRow | null;
	return row ?? null;
}

export function getShareById(id: string): ShareRow | null {
	return getShareRow(id) ?? null;
}

export function getShareBySlug(slug: string): ShareRow | null {
	const row = getDb().prepare('SELECT * FROM shares WHERE slug = ?').get(slug) as ShareRow | null;
	return row ?? null;
}

export function getShareHumanState(shareId: string): {
	status: 'available' | 'burned' | 'expired';
} {
	const row = getShareRow(shareId);
	if (!row) return { status: 'expired' };
	if (row.consumed_at) return { status: 'burned' };
	if (row.expires_at <= now()) return { status: 'expired' };
	return { status: 'available' };
}

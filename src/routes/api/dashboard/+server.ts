import { json, error, type RequestHandler } from '@sveltejs/kit';
import { sessionAccount } from '../auth/_shared';
import {
	listSharesForOwner,
	listReverseByOwner,
	deleteShare,
	deleteReverseShare,
	getShareById,
	getReverseOwner
} from '#lib/server/shares';

type Row = Record<string, unknown>;

export const GET: RequestHandler = async ({ cookies }) => {
	const account = sessionAccount(cookies);
	if (!account) throw error(401, 'sign in required');
	return json({
		account,
		shares: listSharesForOwner(account).map((s) => ({
			id: s.id,
			slug: s.slug,
			kind: s.kind,
			burn: !!s.burn,
			status: s.consumed_at ? 'burned' : s.expires_at <= Date.now() ? 'expired' : 'active',
			fileCount: Number(s.file_count ?? 0),
			totalSize: Number(s.total_size ?? 0),
			expiresAt: s.expires_at,
			createdAt: s.created_at
		})),
		reverse: (listReverseByOwner(account) as Row[]).map((r) => ({
			id: r.id,
			lsug: r.lsug,
			expiresAt: r.expires_at,
			createdAt: r.created_at,
			fileCount: Number(r.file_count ?? 0)
		}))
	});
};

export const DELETE: RequestHandler = async ({ cookies, url }) => {
	const account = sessionAccount(cookies);
	if (!account) throw error(401, 'sign in required');
	const shareId = url.searchParams.get('shareId');
	const reverseId = url.searchParams.get('reverseId');
	if (shareId) {
		const share = getShareById(shareId);
		if (!share || share.owner_account_id !== account) throw error(404, 'not yours');
		deleteShare(shareId);
		return json({ ok: true });
	}
	if (reverseId) {
		if (getReverseOwner(reverseId) !== account) throw error(404, 'not yours');
		deleteReverseShare(reverseId);
		return json({ ok: true });
	}
	throw error(400, 'nothing to delete');
};

void json;

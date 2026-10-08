import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getShareBySlug, getShareHumanState, filesForShare } from '#lib/server/shares';

export const GET: RequestHandler = async ({ params }) => {
	const share = getShareBySlug(params.slug ?? '');
	if (!share) return json({ status: 'expired' }, { status: 404 });
	const state = getShareHumanState(share.id);
	if (state.status !== 'available') {
		return json(
			{ status: state.status, kind: share.kind },
			{ status: state.status === 'burned' ? 410 : 404 }
		);
	}
	return json({
		status: 'available',
		id: share.id,
		kind: share.kind,
		burn: !!share.burn,
		needsPassphrase: !!share.pass_verifier,
		passSalt: share.pass_salt ? Buffer.from(share.pass_salt).toString('base64url') : null,
		expiresAt: share.expires_at,
		files: filesForShare(share.id).map((f) => ({
			id: f.id,
			name: f.name,
			mime: f.mime,
			size: f.size
		}))
	});
};

void error;

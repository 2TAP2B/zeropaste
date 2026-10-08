import { error, type RequestHandler } from '@sveltejs/kit';
import { getStorage } from '#lib/server/storage';
import { resolveActiveFile, requireGate } from '../../_shared';
import { consumeShare, getShareById } from '#lib/server/shares';

/** Download session start: marks burn-on-read consumed, then streams (disk)
 *  or 302s to a presigned URL (s3). Passphrase shares must send the pass
 *  verifier (a derived hash, not key material) in the x-zp-pass header. */
export const GET: RequestHandler = async ({ params, cookies, request }) => {
	requireGate((n) => cookies.get(n));
	const { file, shareSlug, burn } = resolveActiveFile(params.id!);
	if (burn && shareSlug) {
		const result = consumeShare(shareSlug);
		if (!result.ok) throw error(410, result.reason === 'already' ? 'already burned' : 'gone');
	}
	const share = file.share_id ? getShareById(file.share_id) : null;
	if (share?.pass_verifier) {
		const proof = request.headers.get('x-zp-pass') ?? '';
		if (proof !== share.pass_verifier) throw error(401, 'passphrase required');
	}
	const storage = getStorage();
	if (storage.kind === 's3' && storage.downloadUrl) {
		const url = await storage.downloadUrl(file.blob);
		return new Response(null, { status: 302, headers: { location: url } });
	}
	const stream = await storage.get(file.blob);
	return new Response(stream, {
		headers: {
			'content-type': 'application/octet-stream',
			'content-disposition': `attachment; filename="zeropaste-${file.id.slice(0, 8)}.zpc"`,
			'cache-control': 'no-store'
		}
	});
};

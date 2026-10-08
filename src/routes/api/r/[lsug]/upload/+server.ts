import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getReverseByLsug, attachFilesToReverse, type FileMeta } from '#lib/server/shares';
import { gateOk } from '#lib/server/gate-session';

/** friends authorize uploads into the reverse share (public; site gate enforced) */
export const POST: RequestHandler = async ({ params, request, cookies }) => {
	if (!gateOk((n) => cookies.get(n))) throw error(401, 'site passphrase required');
	const reverse = getReverseByLsug(params.lsug ?? '');
	if (!reverse) throw error(410, 'expired or unknown');
	const body = (await request.json()) as { files: FileMeta[] };
	if (!body.files?.length) throw error(400, 'files required');
	const files = await attachFilesToReverse(reverse.id, body.files);
	return json({
		files: files.map((f) => ({
			id: f.id,
			name: f.name,
			mime: f.mime,
			size: f.size,
			upload: f.upload
		}))
	});
};

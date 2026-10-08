import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getReverseByLsug, filesForReverse } from '#lib/server/shares';

export const GET: RequestHandler = async ({ params }) => {
	const reverse = getReverseByLsug(params.lsug ?? '');
	if (!reverse) return json({ status: 'expired' }, { status: 404 });
	return json({
		status: 'available',
		lsug: reverse.lsug,
		files: filesForReverse(reverse.id).map((f) => ({
			id: f.id,
			name: f.name,
			mime: f.mime,
			size: f.size
		}))
	});
};

void error;

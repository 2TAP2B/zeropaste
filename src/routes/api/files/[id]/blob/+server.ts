import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getStorage } from '#lib/server/storage';
import { resolveActiveFile, requireGate } from '../../_shared';

/** disk mode direct ciphertext upload */
export const PUT: RequestHandler = async ({ params, request, cookies }) => {
	requireGate((n) => cookies.get(n));
	const { file } = resolveActiveFile(params.id!);
	if (!request.body) throw error(400, 'empty body');
	await getStorage().put(file.blob, request.body);
	return json({ ok: true });
};

import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getStorage, type UploadPlan } from '#lib/server/storage';
import { resolveActiveFile, requireGate } from '../../_shared';

/** s3 direct uploads: finalize presence (single s3put) or multipart part etags. */
export const POST: RequestHandler = async ({ params, request, cookies }) => {
	requireGate((n) => cookies.get(n));
	const { file } = resolveActiveFile(params.id!);
	const body = (await request.json()) as {
		uploadId?: string;
		kind?: UploadPlan['kind'];
		parts?: { partNumber: number; etag: string }[];
	};
	const storage = getStorage();
	if (storage.kind !== 's3') {
		const size = await storage.sizeOf(file.blob);
		if (size === 0) throw error(400, 'blob missing');
		return json({ ok: true, size });
	}
	if (body.kind === 's3put') {
		const size = await storage.sizeOf(file.blob);
		if (size === 0) throw error(400, 'blob missing');
		return json({ ok: true, size });
	}
	if (!storage.complete) throw error(500, 's3 not initialized');
	if (!body.uploadId || !body.parts?.length) throw error(400, 'uploadId and parts required');
	await storage.complete(file.blob, body.uploadId, body.parts);
	return json({ ok: true, size: await storage.sizeOf(file.blob) });
};

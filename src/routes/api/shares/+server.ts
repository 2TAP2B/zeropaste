import { json, error } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { createShare, type NewShareInput } from '#lib/server/shares';
import { gateOk } from '#lib/server/gate-session';
import { config } from '#lib/server/config';
import { sessionAccount } from '../auth/_shared';

export const POST: RequestHandler = async ({ request, cookies }) => {
	if (!gateOk((name) => cookies.get(name))) throw error(401, 'site passphrase required');
	const body = (await request.json()) as {
		kind?: 'files' | 'paste';
		files?: NewShareInput['files'];
		burn?: boolean;
		ttl?: number;
		passSalt?: string;
		passVerifier?: string;
	};
	if (!body.kind || !body.files?.length || body.files.length > config.maxFiles) {
		throw error(400, 'invalid share payload');
	}
	for (const file of body.files) {
		if (
			!file.name ||
			!file.mime ||
			!Number.isFinite(file.size) ||
			file.size > config.maxFileBytes
		) {
			throw error(400, 'file limits exceeded');
		}
	}
	const { share, files } = await createShare({
		kind: body.kind,
		files: body.files,
		burn: !!body.burn,
		expiresInSecs: Math.max(60, Math.min(90 * 24 * 3600, body.ttl ?? config.defaultTtlSeconds)),
		passSalt: body.passSalt,
		passVerifier: body.passVerifier,
		accountId: sessionAccount(cookies) ?? undefined
	});
	return json({
		slug: share.slug,
		burn: !!share.burn,
		expiresAt: share.expires_at,
		files: files.map((f) => ({
			id: f.id,
			name: f.name,
			mime: f.mime,
			size: f.size,
			upload: f.upload
		}))
	});
};

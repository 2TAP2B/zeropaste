import { json, error, type RequestHandler } from '@sveltejs/kit';
import { sessionAccount } from '../auth/_shared';
import { createReverseShare } from '#lib/server/shares';
import { config } from '#lib/server/config';

/** owner-only creates a reverse share; returns lsug for link building */
export const POST: RequestHandler = async ({ request, cookies }) => {
	const account = sessionAccount(cookies);
	if (!account) throw error(401, 'sign in required');
	const body = (await request.json()) as { lsug?: string; ttl?: number };
	try {
		const { reverseId, lsug } = createReverseShare({
			lsug: body.lsug,
			account,
			expiresInSecs: Math.max(60, Math.min(90 * 24 * 3600, body.ttl ?? config.defaultTtlSeconds))
		});
		return json({ reverseId, lsug });
	} catch (err) {
		throw error(
			400,
			err instanceof Error
				? err.message.includes('UNIQUE')
					? 'slug taken'
					: err.message
				: 'failed'
		);
	}
};

void error;

import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { startAuthentication } from '#lib/server/auth';

export const POST: RequestHandler = async () => {
	const { id, options } = await startAuthentication();
	return json({ id, options });
};

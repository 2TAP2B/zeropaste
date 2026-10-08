import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { startRegistration } from '#lib/server/auth';

export const POST: RequestHandler = async () => {
	const { id, options } = await startRegistration();
	return json({ id, options });
};

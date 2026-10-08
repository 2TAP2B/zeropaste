import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { sessionAccount } from '../_shared';

export const GET: RequestHandler = async ({ cookies }) => {
	const account = sessionAccount(cookies);
	if (!account) return json({ account: null }, { status: 200 });
	return json({ account });
};

import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { destroySession } from '#lib/server/auth';
import { SESSION_COOKIE, clearSessionCookie } from '../_shared';

export const POST: RequestHandler = async ({ cookies }) => {
	const session = cookies.get(SESSION_COOKIE);
	if (session) destroySession(session);
	clearSessionCookie(cookies);
	return json({ ok: true });
};

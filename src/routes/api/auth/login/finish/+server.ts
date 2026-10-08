import { json, error } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { finishAuthentication, createSession } from '#lib/server/auth';
import { setSessionCookie } from '../../_shared';

export const POST: RequestHandler = async ({ request, cookies }) => {
	const body = (await request.json()) as {
		id: string;
		response: AuthenticationResponseJSON;
	};
	try {
		const { account } = await finishAuthentication(body.id, body.response);
		setSessionCookie(cookies, createSession(account));
		return json({ ok: true, account });
	} catch (err) {
		throw error(401, err instanceof Error ? err.message : 'authentication failed');
	}
};

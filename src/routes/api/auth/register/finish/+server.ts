import { json, error } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { finishRegistration, createSession } from '#lib/server/auth';
import { setSessionCookie } from '../../_shared';

export const POST: RequestHandler = async ({ request, cookies }) => {
	const body = (await request.json()) as {
		id: string;
		response: RegistrationResponseJSON;
		prfSalt: string;
	};
	try {
		const { account } = await finishRegistration(body.id, body.response, body.prfSalt);
		setSessionCookie(cookies, createSession(account));
		return json({ ok: true, account, prfSalt: body.prfSalt });
	} catch (err) {
		throw error(400, err instanceof Error ? err.message : 'registration failed');
	}
};

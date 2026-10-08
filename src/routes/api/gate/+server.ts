import { json, error, type RequestHandler } from '@sveltejs/kit';
import { verifySiteGate, siteGateEnabled } from '#lib/server/gate';
import { gateCookie } from '#lib/server/gate-session';

export const POST: RequestHandler = async ({ cookies, request }) => {
	if (!siteGateEnabled()) return json({ ok: true });
	const { passphrase } = (await request.json()) as { passphrase?: string };
	if (!passphrase || !verifySiteGate(passphrase)) throw error(401, 'wrong passphrase');
	const c = gateCookie();
	cookies.set(c.name, c.value, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		maxAge: 30 * 24 * 3600
	});
	return json({ ok: true });
};

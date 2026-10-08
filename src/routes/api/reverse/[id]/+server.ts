import { json, error, type RequestHandler } from '@sveltejs/kit';
import { getReverseById, getReverseOwner } from '#lib/server/shares';
import { getDb } from '#lib/server/db';
import { accountForSession } from '#lib/server/auth';
import type { Cookies } from '@sveltejs/kit';

function ownerAccount(cookies: Cookies): string {
	const account = accountForSession(cookies.get('zp_session'));
	if (!account) throw error(401, 'sign in required');
	return account;
}

/** stores the owner's PRF-wrapped content key for a reverse share (auth) */
export const POST: RequestHandler = async ({ params, request, cookies }) => {
	const account = ownerAccount(cookies);
	const reverseId = params.id!;
	if (getReverseOwner(reverseId) !== account) throw error(404, 'not yours');
	const body = (await request.json()) as {
		credentialId: string;
		nonce: string;
		wrapped: string;
	};
	if (!body.credentialId || !body.nonce || !body.wrapped) throw error(400, 'missing wrap fields');
	getDb()
		.prepare(
			'INSERT OR REPLACE INTO reverse_wraps (reverse_share_id, credential_id, nonce, wrapped) VALUES (?, ?, ?, ?)'
		)
		.run(
			reverseId,
			body.credentialId,
			Buffer.from(body.nonce, 'base64url'),
			Buffer.from(body.wrapped, 'base64url')
		);
	return json({ ok: true });
};

/** owner retrieves wrap to unwrap locally with PRF account key */
export const GET: RequestHandler = async ({ params, cookies }) => {
	const account = ownerAccount(cookies);
	const reverseId = params.id!;
	if (getReverseOwner(reverseId) !== account) throw error(404, 'not yours');
	if (!getReverseById(reverseId)) throw error(410, 'expired');
	const rows = getDb()
		.prepare('SELECT credential_id, nonce, wrapped FROM reverse_wraps WHERE reverse_share_id = ?')
		.all(reverseId) as { credential_id: string; nonce: Buffer; wrapped: Buffer }[];
	return json({
		wraps: rows.map((r) => ({
			credentialId: r.credential_id,
			nonce: r.nonce.toString('base64url'),
			wrapped: r.wrapped.toString('base64url')
		}))
	});
};

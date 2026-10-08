import { json, error } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { prfSaltFor } from '#lib/server/auth';

/** Returns the per-credential PRF salt. Salts are not secrets; the secret comes
 *  from the authenticator hardware. Needed for cross-device passkey PRF eval. */
export const POST: RequestHandler = async ({ request }) => {
	const { credentialId } = (await request.json()) as { credentialId?: string };
	if (!credentialId) throw error(400, 'credentialId required');
	const salt = prfSaltFor(credentialId);
	if (!salt) throw error(404, 'unknown credential');
	return json({ prfSalt: salt });
};

import { randomUUID, randomBytes } from 'node:crypto';
import {
	generateRegistrationOptions,
	generateAuthenticationOptions,
	verifyRegistrationResponse
} from '@simplewebauthn/server';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getDb } from '../db';

export const rp = () => ({ rpId: process.env.ZP_RP_ID ?? 'localhost', rpName: 'ZeroPaste' });

export const originOf = (requestOrigin: string): string => process.env.ZP_ORIGIN ?? requestOrigin;

export interface StoredChallenge {
	kind: 'register' | 'login';
	challenge: string;
	accountId?: string;
}

export const createChallenge = (
	kind: 'register' | 'login',
	accountId?: string
): {
	id: string;
	options: { challenge: string; rpId: string; rpName: string };
} => {
	const id = randomUUID();
	const challenge = randomBytes(32).toString('base64url');
	getDb()
		.prepare('INSERT INTO challenges (id, payload, expires_at) VALUES (?, ?, ?)')
		.run(id, JSON.stringify({ kind, challenge, accountId }), Date.now() + 5 * 60 * 1000);
	const { rpId, rpName } = rp();
	return { id: `${kind}:${id}`, options: { challenge, rpId, rpName } };
};

export const popChallenge = (key: string): StoredChallenge => {
	const [kindRaw, id] = key.split(':');
	const row = getDb()
		.prepare('SELECT payload FROM challenges WHERE id = ? AND expires_at > ?')
		.get(id, Date.now()) as { payload: string } | undefined;
	getDb().prepare('DELETE FROM challenges WHERE id = ?').run(id);
	if (!row) throw new Error('challenge expired');
	const parsed = JSON.parse(row.payload) as StoredChallenge;
	if (parsed.kind !== kindRaw) throw new Error('challenge kind mismatch');
	return parsed;
};

export async function startRegistration(): Promise<{ id: string; options: object }> {
	const reg = createChallenge('register');
	const options = await generateRegistrationOptions({
		rpName: reg.options.rpName,
		rpID: reg.options.rpId,
		userName: `zp-${randomBytes(4).toString('hex')}`,
		authenticatorSelection: {
			residentKey: 'required',
			userVerification: 'required'
		},
		extensions: { prf: {} }
	});
	return { id: reg.id, options };
}

export async function finishRegistration(
	challengeKey: string,
	response: RegistrationResponseJSON,
	prfSaltB64: string
): Promise<{ account: string; prfSalt: string }> {
	const challenge = popChallenge(challengeKey);
	if (challenge.kind !== 'register') throw new Error('wrong challenge');
	const { origin } = originParts();
	const verification = await verifyRegistrationResponse({
		response,
		expectedChallenge: challenge.challenge,
		expectedOrigin: [origin],
		expectedRPID: [rp().rpId],
		requireUserVerification: true
	});
	if (!verification.verified || !verification.registrationInfo)
		throw new Error('registration failed');
	const { credential } = verification.registrationInfo;
	const accountId = randomUUID();
	const db = getDb();
	db.prepare('INSERT INTO accounts (id, created_at) VALUES (?, ?)').run(accountId, Date.now());
	const salt = Buffer.from(prfSaltB64, 'base64url');
	if (salt.length !== 32) throw new Error('bad prf salt');
	db.prepare(
		'INSERT INTO credentials (id, account_id, public_key, counter, transports, prf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
	).run(credential.id, accountId, Buffer.from(credential.publicKey), 0, null, salt, Date.now());
	return { account: accountId, prfSalt: prfSaltB64 };
}

export async function startAuthentication(): Promise<{ id: string; options: object }> {
	const chal = createChallenge('login');
	const options = await generateAuthenticationOptions({
		rpID: rp().rpId,
		userVerification: 'required',
		extensions: {}
	});
	return { id: chal.id, options };
}

export async function finishAuthentication(
	challengeKey: string,
	response: AuthenticationResponseJSON
): Promise<{ account: string; credential: string }> {
	const challenge = popChallenge(challengeKey);
	if (challenge.kind !== 'login') throw new Error('wrong challenge');
	const credentialId = response.id;
	const db = getDb();
	const credRow = db.prepare('SELECT * FROM credentials WHERE id = ?').get(credentialId) as
		{ id: string; account_id: string; public_key: Buffer; counter: number } | undefined;
	if (!credRow) throw new Error('unknown credential');
	const { origin } = originParts();
	const verification = await verifyAuthenticationResponse({
		response,
		expectedChallenge: challenge.challenge,
		expectedOrigin: [origin],
		expectedRPID: [rp().rpId],
		credential: {
			id: credRow.id,
			publicKey: new Uint8Array(credRow.public_key),
			counter: credRow.counter
		},
		requireUserVerification: true
	});
	if (!verification.verified) throw new Error('authentication failed');
	db.prepare('UPDATE credentials SET counter = ? WHERE id = ?').run(
		verification.authenticationInfo.newCounter,
		credRow.id
	);
	return { account: credRow.account_id, credential: credRow.id };
}

export const prfSaltFor = (credentialId: string): string | null => {
	const row = getDb().prepare('SELECT prf_salt FROM credentials WHERE id = ?').get(credentialId) as
		{ prf_salt: Buffer } | undefined;
	return row ? Buffer.from(row.prf_salt).toString('base64url') : null;
};

// sessions
export const createSession = (account: string): string => {
	const id = randomBytes(32).toString('base64url');
	getDb()
		.prepare('INSERT INTO sessions (id, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
		.run(id, account, Date.now(), Date.now() + 30 * 24 * 3600 * 1000);
	return id;
};

export const accountForSession = (sessionId: string | undefined): string | null => {
	if (!sessionId) return null;
	const row = getDb()
		.prepare('SELECT account_id FROM sessions WHERE id = ? AND expires_at > ?')
		.get(sessionId, Date.now()) as { account_id: string } | undefined;
	return row?.account_id ?? null;
};

export const destroySession = (sessionId: string): void => {
	getDb().prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
};

function originParts(): { origin: string } {
	const rpid = rp().rpId;
	const origin = process.env.ZP_ORIGIN ?? `https://${rpid}`;
	return { origin };
}

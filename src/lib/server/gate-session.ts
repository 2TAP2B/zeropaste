import { createHash } from 'node:crypto';
import { config } from './config';
import { siteGateEnabled } from './gate';

const GATE_COOKIE = 'zp_gate';

const gateToken = (): string =>
	createHash('sha256').update(`${config.sitePassphrase}#zp-gate-v1`).digest('base64url');

export function gateOk(get: (name: string) => string | undefined): boolean {
	if (!siteGateEnabled()) return true;
	return get(GATE_COOKIE) === gateToken();
}

export const gateCookie = (): { name: string; value: string } => ({
	name: GATE_COOKIE,
	value: gateToken()
});

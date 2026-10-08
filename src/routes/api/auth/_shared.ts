import type { Cookies } from '@sveltejs/kit';
import { accountForSession } from '#lib/server/auth';

export const SESSION_COOKIE = 'zp_session';

export function setSessionCookie(cookies: Cookies, value: string): void {
	cookies.set(SESSION_COOKIE, value, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		maxAge: 30 * 24 * 3600
	});
}

export function clearSessionCookie(cookies: Cookies): void {
	cookies.delete(SESSION_COOKIE, { path: '/' });
}

export function sessionAccount(cookies: Cookies): string | null {
	return accountForSession(cookies.get(SESSION_COOKIE));
}

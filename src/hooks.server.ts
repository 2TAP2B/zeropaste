import type { Handle } from '@sveltejs/kit/hooks';
import { openDb } from '#lib/server/db';
import { config } from '#lib/server/config';
import { purge } from '#lib/server/shares';

const g = globalThis as typeof globalThis & { __zp_cleanup?: NodeJS.Timeout };

export const handle: Handle = async ({ event, resolve }) => {
	openDb(`${config.dataDir}/zp.db`);
	scheduleCleanup();
	return resolve(event);
};

function scheduleCleanup(): void {
	if (g.__zp_cleanup) return;
	g.__zp_cleanup = setInterval(
		() => {
			void purge().catch(() => {});
		},
		5 * 60 * 1000
	);
	if (g.__zp_cleanup.unref) g.__zp_cleanup.unref();
}

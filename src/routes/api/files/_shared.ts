import { error } from '@sveltejs/kit';
import {
	fileForFileId,
	getShareHumanState,
	getShareById,
	getReverseById,
	type FileRow
} from '#lib/server/shares';
import { gateOk } from '#lib/server/gate-session';

export interface ResolvedFile {
	file: FileRow;
	shareSlug?: string;
	burn: boolean;
}

/** 404s if unknown, 410 if its parent share/reverse is consumed or expired. */
export function resolveActiveFile(id: string): ResolvedFile {
	const file = fileForFileId(id);
	if (!file) throw error(404, 'no such file');
	if (file.share_id) {
		const state = getShareHumanState(file.share_id);
		if (state.status !== 'available') throw error(410, 'share is gone (burned or expired)');
		const share = getShareById(file.share_id);
		if (!share) throw error(410, 'share is gone');
		return { file, shareSlug: share.slug, burn: !!share.burn };
	}
	if (file.reverse_share_id) {
		const reverse = getReverseById(file.reverse_share_id);
		if (!reverse) throw error(410, 'reverse share expired');
		return { file, burn: false };
	}
	throw error(404, 'orphan file');
}

export function requireGate(get: (name: string) => string | undefined): void {
	if (!gateOk(get)) throw error(401, 'site passphrase required');
}

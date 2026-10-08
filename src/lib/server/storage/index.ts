import { config } from '../config';
import { diskStorage } from './disk';
import { s3Storage } from './s3';
import type { StorageContext } from './types';

let storage: StorageContext | null = null;

export const getStorage = (): StorageContext => {
	if (!storage) {
		storage = config.storage === 's3' ? s3Storage() : diskStorage(config.dataDir);
	}
	return storage;
};

export type { StorageContext, UploadPlan } from './types';

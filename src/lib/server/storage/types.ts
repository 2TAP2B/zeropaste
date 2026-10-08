export type StorageKind = 'disk' | 's3';

export type UploadPlan =
	| { kind: 'direct' }
	| { kind: 's3'; uploadId: string; partUrls: { url: string; partNumber: number }[] }
	| { kind: 's3put'; url: string };

export interface StorageContext {
	kind: StorageKind;
	plan: (key: string, size: number) => Promise<UploadPlan>;
	/** s3 multipart: finalize the upload */
	complete?(
		key: string,
		uploadId: string,
		parts: { partNumber: number; etag: string }[]
	): Promise<void>;
	/** s3: presigned GET url for direct browser downloads */
	downloadUrl?(key: string): Promise<string>;
	put(key: string, stream: ReadableStream<Uint8Array>): Promise<void>;
	get(key: string): Promise<ReadableStream<Uint8Array>>;
	sizeOf(key: string): Promise<number>;
	delete(keys: string[]): Promise<void>;
	exists(key: string): Promise<boolean>;
}

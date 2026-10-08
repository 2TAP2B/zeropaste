import assert from 'node:assert/strict';

const num = (value: string | undefined, fallback: number): number => {
	const parsed = Number(value);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const dataDir = process.env.ZP_DATA_DIR ?? `${process.cwd()}/data`;

export const config = {
	dataDir,
	storage: (process.env.ZP_STORAGE === 's3' ? 's3' : 'disk') as 'disk' | 's3',
	sitePassphrase: process.env.ZP_SITE_PASSPHRASE ?? '',
	maxFileBytes: num(process.env.ZP_MAX_FILE_MB, 1000) * 1024 * 1024,
	maxFiles: num(process.env.ZP_MAX_FILES, 1_000_000),
	defaultTtlSeconds: num(process.env.ZP_DEFAULT_TTL_SECS, 7 * 24 * 3600),
	port: num(process.env.ZP_PORT, 3000),
	rpId: process.env.ZP_RP_ID ?? 'localhost',
	origin: process.env.ZP_ORIGIN ?? '',
	s3: {
		endpoint: process.env.ZP_S3_ENDPOINT ?? '',
		bucket: process.env.ZP_S3_BUCKET ?? '',
		region: process.env.ZP_S3_REGION ?? 'us-east-1',
		accessKeyId: process.env.ZP_S3_ACCESS_KEY_ID ?? '',
		secretAccessKey: process.env.ZP_S3_SECRET_ACCESS_KEY ?? '',
		prefix: (process.env.ZP_S3_PREFIX ?? '').replace(/^\/+|\/+$/g, '')
	}
};

if (config.storage === 's3') {
	assert.ok(config.s3.bucket, 'ZP_S3_BUCKET required when ZP_STORAGE=s3');
	assert.ok(config.s3.accessKeyId, 'ZP_S3_ACCESS_KEY_ID required when ZP_STORAGE=s3');
	assert.ok(config.s3.secretAccessKey, 'ZP_S3_SECRET_ACCESS_KEY required when ZP_STORAGE=s3');
}

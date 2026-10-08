import {
	S3Client,
	CreateMultipartUploadCommand,
	UploadPartCommand,
	PutObjectCommand,
	CompleteMultipartUploadCommand,
	GetObjectCommand,
	HeadObjectCommand,
	DeleteObjectsCommand
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Readable } from 'node:stream';
import { config } from '../config';
import type { StorageContext, UploadPlan } from './types';

const PART_SIZE = 5 * 1024 * 1024;
const PARTS_LIMIT = 10_000;
const PRESIGN_TTL = 3600;

export const s3Storage = (): StorageContext => {
	const client = new S3Client({
		region: config.s3.region,
		endpoint: config.s3.endpoint || undefined,
		forcePathStyle: !!config.s3.endpoint,
		credentials: {
			accessKeyId: config.s3.accessKeyId,
			secretAccessKey: config.s3.secretAccessKey
		}
	});
	const keyOf = (key: string) => (config.s3.prefix ? `${config.s3.prefix}/${key}` : key);
	const bucket = config.s3.bucket;

	return {
		kind: 's3',
		async plan(key, size): Promise<UploadPlan> {
			const full = keyOf(key);
			if (size <= PART_SIZE) {
				const url = await getSignedUrl(
					client,
					new PutObjectCommand({ Bucket: bucket, Key: full }),
					{ expiresIn: PRESIGN_TTL }
				);
				return { kind: 's3put', url };
			}
			const created = await client.send(
				new CreateMultipartUploadCommand({ Bucket: bucket, Key: full })
			);
			if (!created.UploadId) throw new Error('multipart init failed');
			const partCount = Math.min(PARTS_LIMIT, Math.ceil(size / PART_SIZE));
			const partUrls = await Promise.all(
				Array.from({ length: partCount }, async (_, i) => ({
					partNumber: i + 1,
					url: await getSignedUrl(
						client,
						new UploadPartCommand({
							Bucket: bucket,
							Key: full,
							UploadId: created.UploadId,
							PartNumber: i + 1
						}),
						{ expiresIn: PRESIGN_TTL }
					)
				}))
			);
			return { kind: 's3', uploadId: created.UploadId, partUrls };
		},
		async complete(key, uploadId, parts) {
			await client.send(
				new CompleteMultipartUploadCommand({
					Bucket: bucket,
					Key: keyOf(key),
					UploadId: uploadId,
					MultipartUpload: {
						Parts: parts
							.sort((a, b) => a.partNumber - b.partNumber)
							.map((p) => ({ PartNumber: p.partNumber, ETag: p.etag }))
					}
				})
			);
		},
		async downloadUrl(key) {
			return getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: keyOf(key) }), {
				expiresIn: PRESIGN_TTL
			});
		},
		async put(key, stream) {
			const body = await new Response(
				stream as unknown as ReadableStream<Uint8Array>
			).arrayBuffer();
			await client.send(
				new PutObjectCommand({ Bucket: bucket, Key: keyOf(key) as string, Body: Buffer.from(body) })
			);
		},
		async get(key) {
			const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: keyOf(key) }));
			return Readable.toWeb(res.Body as Readable) as ReadableStream<Uint8Array>;
		},
		async sizeOf(key) {
			const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: keyOf(key) }));
			return head.ContentLength ?? 0;
		},
		async delete(keys) {
			const objects = keys.map((key) => ({ Key: keyOf(key) }));
			for (let i = 0; i < objects.length; i += 1000) {
				await client.send(
					new DeleteObjectsCommand({
						Bucket: bucket,
						Delete: { Objects: objects.slice(i, i + 1000) }
					})
				);
			}
		},
		async exists(key) {
			try {
				await client.send(new HeadObjectCommand({ Bucket: bucket, Key: keyOf(key) }));
				return true;
			} catch {
				return false;
			}
		}
	};
};

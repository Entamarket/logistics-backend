import { randomUUID } from "crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);

const EXT_BY_MIME: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
};

function getS3Prefix(): string {
  return (process.env.AWS_S3_PREFIX || "logistics").replace(/^\/+|\/+$/g, "");
}

function getBucketName(): string {
  const bucket = process.env.AWS_BUCKET_NAME?.trim();
  if (!bucket) {
    throw new Error("AWS_BUCKET_NAME is not configured");
  }
  return bucket;
}

function getS3Client(): S3Client {
  const accessKeyId = process.env.AWS_ACCESS_KEY?.trim();
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY?.trim();
  const region = process.env.AWS_REGION?.trim();
  if (!accessKeyId || !secretAccessKey || !region) {
    throw new Error("AWS credentials or region are not configured");
  }
  return new S3Client({
    region,
    credentials: { accessKeyId, secretAccessKey },
  });
}

export function validateDeliveryProofImage(contentType: string, sizeBytes: number): void {
  if (!ALLOWED_MIME.has(contentType)) {
    throw new Error("Photo must be JPEG, PNG, or WebP");
  }
  if (sizeBytes <= 0 || sizeBytes > MAX_BYTES) {
    throw new Error("Photo must be between 1 byte and 5 MB");
  }
}

export function buildDeliveryProofObjectKey(shipmentId: string, contentType: string): string {
  const ext = EXT_BY_MIME[contentType] ?? "jpg";
  const prefix = getS3Prefix();
  return `${prefix}/delivery-proofs/${shipmentId}/${randomUUID()}.${ext}`;
}

export async function uploadDeliveryProof(
  shipmentId: string,
  buffer: Buffer,
  contentType: string
): Promise<{ key: string }> {
  validateDeliveryProofImage(contentType, buffer.length);
  const key = buildDeliveryProofObjectKey(shipmentId, contentType);
  const client = getS3Client();
  await client.send(
    new PutObjectCommand({
      Bucket: getBucketName(),
      Key: key,
      Body: buffer,
      ContentType: contentType,
    })
  );
  return { key };
}

export async function deleteDeliveryProofObject(key: string): Promise<void> {
  if (!key.trim()) return;
  try {
    const client = getS3Client();
    await client.send(
      new DeleteObjectCommand({
        Bucket: getBucketName(),
        Key: key,
      })
    );
  } catch {
    /* best-effort cleanup */
  }
}

export async function getDeliveryProofSignedUrl(key: string, expiresInSeconds = 3600): Promise<string> {
  if (!key.trim()) {
    throw new Error("Delivery proof image key is required");
  }
  const client = getS3Client();
  return getSignedUrl(
    client,
    new GetObjectCommand({
      Bucket: getBucketName(),
      Key: key,
    }),
    { expiresIn: expiresInSeconds }
  );
}

export function hasDeliveryProof(shipment: {
  deliveryProofImageKey?: string | null;
  senderConfirmedReceipt?: boolean | null;
}): boolean {
  return Boolean(shipment.deliveryProofImageKey?.trim()) || Boolean(shipment.senderConfirmedReceipt);
}

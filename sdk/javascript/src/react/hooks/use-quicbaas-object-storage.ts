/**
 * QuicBaaS ObjectStorage React Hooks
 *
 * Provides access to the QuicBaaS ObjectStorage services for S3-compatible
 * object storage operations and bucket administration.
 *
 * @packageDocumentation
 */

import type { ObjectStorageService } from '../../services/quicbaas/object-storage-service.js';
import type { ObjectStorageAdminService } from '../../services/quicbaas/object-storage-admin-service.js';
import { usePlatformClient } from '../context.js';

/**
 * Hook to access the QuicBaaS ObjectStorage service
 *
 * Provides methods for S3-compatible object storage operations including
 * uploading, downloading, listing, and deleting objects.
 *
 * @returns The ObjectStorageService instance from the current client
 *
 * @example
 * ```tsx
 * function ObjectStorageManager() {
 *   const objectStorage = useQuicBaaSObjectStorage();
 *
 *   const uploadObject = async (file: File) => {
 *     const result = await objectStorage.putObject({
 *       bucket: 'my-bucket',
 *       key: `uploads/${file.name}`,
 *       body: await file.arrayBuffer(),
 *       contentType: file.type,
 *     });
 *     console.log('Uploaded:', result.data?.etag);
 *   };
 *
 *   const downloadObject = async (key: string) => {
 *     const result = await objectStorage.getObject({
 *       bucket: 'my-bucket',
 *       key,
 *     });
 *     console.log('Downloaded:', result.data?.body);
 *   };
 *
 *   const listObjects = async () => {
 *     const result = await objectStorage.listObjects({
 *       bucket: 'my-bucket',
 *       prefix: 'uploads/',
 *     });
 *     console.log('Objects:', result.data?.objects);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSObjectStorage(): ObjectStorageService {
  const client = usePlatformClient();
  return client.quicBaaSObjectStorage;
}

/**
 * Hook to access the QuicBaaS ObjectStorage Admin service
 *
 * Provides methods for bucket administration including creating,
 * deleting, and configuring buckets, as well as managing bucket
 * policies and lifecycle rules.
 *
 * @returns The ObjectStorageAdminService instance from the current client
 *
 * @example
 * ```tsx
 * function BucketManager() {
 *   const objectStorageAdmin = useQuicBaaSObjectStorageAdmin();
 *
 *   const createBucket = async () => {
 *     const result = await objectStorageAdmin.createBucket({
 *       name: 'my-new-bucket',
 *       region: 'us-east-1',
 *     });
 *     console.log('Bucket created:', result.data);
 *   };
 *
 *   const listBuckets = async () => {
 *     const result = await objectStorageAdmin.listBuckets();
 *     console.log('Buckets:', result.data?.buckets);
 *   };
 *
 *   const setBucketPolicy = async () => {
 *     const result = await objectStorageAdmin.putBucketPolicy({
 *       bucket: 'my-bucket',
 *       policy: {
 *         Version: '2012-10-17',
 *         Statement: [
 *           {
 *             Effect: 'Allow',
 *             Principal: '*',
 *             Action: ['s3:GetObject'],
 *             Resource: ['arn:aws:s3:::my-bucket/*'],
 *           },
 *         ],
 *       },
 *     });
 *     console.log('Policy set:', result.data);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSObjectStorageAdmin(): ObjectStorageAdminService {
  const client = usePlatformClient();
  return client.quicBaaSObjectStorageAdmin;
}

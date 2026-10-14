# JavaScript SDK Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Using the `trusted-platform-sdk` JavaScript/TypeScript SDK in `sdk/javascript`.

The JavaScript SDK provides a TypeScript-first client for the Trusted Platform, designed for browser and Node.js environments with built-in React integration.

## Installation

```bash
npm install trusted-platform-sdk
```

Or with yarn:

```bash
yarn add trusted-platform-sdk
```

## Quick Start

```typescript
import { PlatformClient } from 'trusted-platform-sdk';

// Create client instance
const client = new PlatformClient({
  baseUrl: 'https://platform.example.com',
});

// Get platform health
const health = await client.platform.getHealth({ includeServices: true });
if (health.data) {
  console.log('Platform status:', health.data.status);
}

// Issue a certificate
const cert = await client.ca.issueCertificate({
  subject: { commonName: 'server.example.com' },
  validDays: 365,
});
if (cert.data) {
  console.log('Certificate serial:', cert.data.serial);
}
```

## React Integration

### Provider Setup

Wrap your application with `PlatformProvider`:

```tsx
import { PlatformProvider } from 'trusted-platform-sdk/react';

function App() {
  return (
    <PlatformProvider
      config={{
        baseUrl: 'https://platform.example.com',
        credentials: 'include',
      }}
    >
      <YourApplication />
    </PlatformProvider>
  );
}
```

### Using Hooks

#### usePlatformClient

Access the client instance directly:

```tsx
import { usePlatformClient } from 'trusted-platform-sdk/react';

function Dashboard() {
  const client = usePlatformClient();

  const handleClick = async () => {
    const result = await client.platform.getVersion();
    console.log(result.data);
  };

  return <button onClick={handleClick}>Get Version</button>;
}
```

#### useApi Hook

Declarative data fetching with automatic state management:

```tsx
import { useApi, usePlatformClient } from 'trusted-platform-sdk/react';

function CertificateList() {
  const client = usePlatformClient();

  const { data, isLoading, error, refetch } = useApi(
    () => client.ca.listCertificates({ page: 1, pageSize: 50 }),
    [], // Dependencies array
    {
      refetchInterval: 30000, // Poll every 30s
      onSuccess: (data) => console.log('Fetched certificates'),
      onError: (error) => console.error('Fetch failed:', error),
    }
  );

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <ul>
      {data?.certificates.map((cert) => (
        <li key={cert.serial}>
          {cert.subject} - Expires: {cert.notAfter}
        </li>
      ))}
    </ul>
  );
}
```

#### useMutation Hook

Handle POST/PUT/DELETE operations with loading states:

```tsx
import { useMutation, useCA } from 'trusted-platform-sdk/react';

function IssueCertificateForm() {
  const ca = useCA();
  const [commonName, setCommonName] = useState('');

  const issueCert = useMutation(
    (request: CertificateRequest) => ca.issueCertificate(request),
    {
      onSuccess: (cert, variables) => {
        toast.success(`Certificate ${cert.serial} issued`);
        setCommonName('');
      },
      onError: (error) => {
        toast.error(`Failed: ${error.message}`);
      },
    }
  );

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    issueCert.mutate({
      subject: { commonName },
      validDays: 365,
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={commonName}
        onChange={(e) => setCommonName(e.target.value)}
        placeholder="Common Name"
      />
      <button type="submit" disabled={issueCert.isLoading}>
        {issueCert.isLoading ? 'Issuing...' : 'Issue Certificate'}
      </button>
    </form>
  );
}
```

### Service-Specific Hooks

Convenience hooks for each service:

```tsx
import {
  useAttestation,
  useCA,
  useCompute,
  useDevice,
  useDNS,
  useGateway,
  useIAM,
  useIDevID,
  useKMS,
  useOverlay,
  usePlatform,
  usePXE,
  useSDN,
  useTenant,
  useTPM,
  useVTPM,
} from 'trusted-platform-sdk/react';

function TPMOperations() {
  const tpm = useTPM();

  const handleSeal = async (data: string) => {
    const result = await tpm.seal({
      data: btoa(data),
      cn: 'sealed-secret',
      pcrIndices: [0, 1, 7],
    });
    return result.data;
  };

  // ... render
}
```

## Data Platform Services

The JavaScript SDK provides access to data, AI/ML, security, and infrastructure platform services through a unified interface.

### Service Categories

| Category | Services | Count |
|----------|----------|-------|
| Data | kv, batch, transaction, query, timeseries, backup | 6 |
| AI/ML | vector, embedding, ollama | 3 |
| Security | auth, dataKms, secrets, crypto, dynamicSecrets, certificate, seal, rbac, clusterDek | 9 |
| Infrastructure | cluster, health, operations, cache, parameterStore, scheduler, objectStorage, objectStorageAdmin, objectTransfer | 9 |
| Identity | dataIam (with sub-clients) | 1 |

### KV Operations

```typescript
// Put a value
await client.kv.put({
  key: 'users/user-123',
  value: JSON.stringify({ name: 'John', email: 'john@example.com' }),
});

// Get a value
const result = await client.kv.get({ key: 'users/user-123' });
if (result.data) {
  const user = JSON.parse(result.data.value);
  console.log('User:', user.name);
}

// List keys with prefix
const keys = await client.kv.list({ prefix: 'users/', limit: 100 });

// Delete a key
await client.kv.delete({ key: 'users/user-123' });
```

### Vector Search

```typescript
// Upsert vectors
await client.vector.upsert({
  namespace: 'documents',
  vectors: [
    { id: 'doc-1', values: embedding1, metadata: { title: 'Document 1' } },
    { id: 'doc-2', values: embedding2, metadata: { title: 'Document 2' } },
  ],
});

// Search similar vectors
const results = await client.vector.searchSimilar({
  namespace: 'documents',
  vector: queryEmbedding,
  topK: 10,
  filter: { category: 'technical' },
});

if (results.data) {
  results.data.matches.forEach((match) => {
    console.log(`Match: ${match.id} (score: ${match.score})`);
  });
}
```

### Embedding Generation

```typescript
// Generate embedding
const embeddingResult = await client.embedding.generate({
  input: 'Hello, world!',
  provider: 'voyage',
  model: 'voyage-3',
});

// Batch embedding
const batchResult = await client.embedding.generateBatch({
  inputs: ['text 1', 'text 2', 'text 3'],
  provider: 'voyage',
});
```

### Secrets Management

```typescript
// Store a secret
await client.secrets.put({
  path: 'apps/myapp/database',
  data: {
    password: 'secret123',
    host: 'db.example.com',
    port: '5432',
  },
});

// Get a secret
const secret = await client.secrets.get({ path: 'apps/myapp/database' });
if (secret.data) {
  console.log('DB Host:', secret.data.data.host);
}

// List secrets
const secretsList = await client.secrets.list({ prefix: 'apps/myapp/' });
```

### Data Key Management

```typescript
// Generate a key
const key = await client.dataKms.generateKey({
  keyId: 'my-encryption-key',
  algorithm: 'AES-256-GCM',
});

// Encrypt data
const encrypted = await client.dataKms.encrypt({
  keyId: 'my-encryption-key',
  plaintext: btoa('sensitive data'),
});

// Decrypt data
const decrypted = await client.dataKms.decrypt({
  keyId: 'my-encryption-key',
  ciphertext: encrypted.data!.ciphertext,
});
```

### Cache Operations

```typescript
// Set cache entry
await client.cache.set({
  key: 'session:user-123',
  value: JSON.stringify({ userId: 'user-123', roles: ['admin'] }),
  ttlSeconds: 3600,
});

// Get cache entry
const cached = await client.cache.get({ key: 'session:user-123' });

// Get cache stats
const stats = await client.cache.stats();
console.log('Cache hit rate:', stats.data?.hitRate);
```

### Health Checks

```typescript
// Ping
const ping = await client.health.ping();

// Liveness check
const liveness = await client.health.liveness();

// Readiness check
const readiness = await client.health.readiness();
```

### Scheduled Jobs

```typescript
// Create a scheduled job
const job = await client.scheduler.createJob({
  name: 'daily-backup',
  schedule: '0 2 * * *',
  payload: JSON.stringify({ type: 'backup', target: 'all' }),
});

// List jobs
const jobs = await client.scheduler.listJobs();

// Delete a job
await client.scheduler.deleteJob({ jobId: job.data!.id });
```

### Data IAM

```typescript
// Create a user
const user = await client.dataIam.createUser({
  username: 'jdoe',
  email: 'user@example.com',
  displayName: 'John Doe',
});

// Create a policy and attach it to the user
const policy = await client.dataIam.createPolicy({
  name: 'secrets-access',
  document: JSON.stringify({
    effect: 'allow',
    actions: ['read', 'write'],
    resources: ['secrets/*'],
  }),
});
await client.dataIam.attachPolicy({
  policyId: policy.data!.policy.id,
  targetType: 'user',
  targetId: user.data!.user.id,
});
```

There are no IAM groups: go-quicbaas removed them (see [`docs/iam/`](../iam/)),
so `dataIam` manages users and attaches policies to users only. Grant access
through roles and policies.

## React Hooks for Platform Services

The SDK provides React hooks for commonly used platform services:

```tsx
import {
  useQuicBaaSKV,
  useQuicBaaSVector,
  useQuicBaaSEmbedding,
  useQuicBaaSSecrets,
  useQuicBaaSCache,
  useQuicBaaSHealth,
} from 'trusted-platform-sdk/react';

function DataManager() {
  const kv = useQuicBaaSKV();
  const vector = useQuicBaaSVector();
  const embeddingSvc = useQuicBaaSEmbedding();
  const secrets = useQuicBaaSSecrets();
  const cache = useQuicBaaSCache();
  const healthSvc = useQuicBaaSHealth();

  // Use with useApi for data fetching
  const { data: healthStatus } = useApi(
    () => healthSvc.ping(),
    [],
    { refetchInterval: 30000 }
  );

  // Use with useMutation for write operations
  const storeSecret = useMutation(
    (req) => secrets.put(req),
    { onSuccess: () => console.log('Secret stored') }
  );

  return (
    <div>
      <p>Platform Status: {healthStatus?.status}</p>
      <button onClick={() => storeSecret.mutate({
        path: 'app/config',
        data: { key: 'value' }
      })}>
        Store Secret
      </button>
    </div>
  );
}
```

### Vector Search with Embedding Generation

```tsx
import { useQuicBaaSVector, useQuicBaaSEmbedding, useApi, useMutation } from 'trusted-platform-sdk/react';

function SemanticSearch() {
  const vector = useQuicBaaSVector();
  const embeddingSvc = useQuicBaaSEmbedding();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  const search = useMutation(
    async (searchQuery: string) => {
      // Generate embedding for query
      const embResult = await embeddingSvc.generate({
        input: searchQuery,
        provider: 'voyage',
      });

      // Search for similar vectors
      return vector.searchSimilar({
        namespace: 'documents',
        vector: embResult.data!.embedding,
        topK: 10,
      });
    },
    {
      onSuccess: (data) => setResults(data.data?.matches || []),
    }
  );

  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      <button onClick={() => search.mutate(query)} disabled={search.isLoading}>
        {search.isLoading ? 'Searching...' : 'Search'}
      </button>
      <ul>
        {results.map((match) => (
          <li key={match.id}>{match.id} (score: {match.score.toFixed(4)})</li>
        ))}
      </ul>
    </div>
  );
}
```

## Service Client Usage

### Platform Service

```typescript
// Get platform version
const version = await client.platform.getVersion();

// Check health with service details
const health = await client.platform.getHealth({ includeServices: true });

// Get system information
const system = await client.platform.getSystemInfo();
```

### Certificate Authority

```typescript
// List certificates
const certs = await client.ca.listCertificates({
  page: 1,
  pageSize: 50,
  status: 'valid',
});

// Issue certificate
const cert = await client.ca.issueCertificate({
  subject: {
    commonName: 'server.example.com',
    organization: ['Example Corp'],
  },
  dnsNames: ['server.example.com', 'localhost'],
  validDays: 365,
});

// Get certificate by serial
const retrieved = await client.ca.getCertificate(cert.data!.serial);

// Revoke certificate
await client.ca.revokeCertificate({
  serial: cert.data!.serial,
  reason: 'keyCompromise',
});

// Download certificate bundle
const bundle = await client.ca.getBundle();
```

### TPM Operations

```typescript
// Get TPM info (GET /api/v1/tpm/info; client.platform.getTPMInfo() is the same
// call). Success means a TPM is available; the payload is the flat
// TPMInfoResponse, e.g. info.data.version === 'TPM_VERSION_2_0'.
const info = await client.tpm.getInfo();

// Seal data to PCRs
const sealed = await client.tpm.seal({
  data: btoa('secret-data'),
  cn: 'my-secret',
  pcrIndices: [0, 1, 7],
});

// Unseal data
const unsealed = await client.tpm.unseal({
  sealedData: sealed.data!.sealedData,
});

// Get attestation quote
const quote = await client.tpm.quote({
  pcrIndices: [0, 1, 2, 3, 4, 5, 6, 7],
  nonce: crypto.randomUUID(),
});
```

### Virtual TPM Management

```typescript
// Create vTPM bundle
const bundle = await client.vtpm.createBundle({
  options: {
    hostname: 'vm-001',
    ekAlgorithm: 'RSA',
  },
});

// List vTPM bundles
const bundles = await client.vtpm.listBundles();

// Get and validate a bundle
const fetched = await client.vtpm.getBundle(bundleId);
const validation = await client.vtpm.validateBundle(bundleId);

// Delete a bundle
await client.vtpm.deleteBundle(bundleId);
```

### IAM Service

```typescript
// Create user
const user = await client.iam.createUser({
  tenantId: 'default',
  email: 'user@example.com',
  name: 'New User',
  roles: ['operator'],
});

// List users
const users = await client.iam.listUsers({
  tenantId: 'default',
  page: 1,
  pageSize: 50,
});

// Create role
const role = await client.iam.createRole({
  name: 'custom-role',
  permissions: ['certificates:read', 'devices:read'],
});

// Assign role to user
await client.iam.assignRole({
  userId: user.data!.id,
  roleId: role.data!.id,
});
```

### KMS Service

```typescript
// Create encryption key
const key = await client.kms.generateKey({
  name: 'my-encryption-key',
  keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'] },
});

// Encrypt data
const encrypted = await client.kms.encrypt({
  keyId: 'my-encryption-key',
  plaintext: btoa('sensitive data'),
});

// Decrypt data
const decrypted = await client.kms.decrypt({
  keyId: 'my-encryption-key',
  ciphertext: encrypted.data!.ciphertext,
});

// Generate random bytes
const random = await client.kms.generateRandom({ numBytes: 32 });
```

## Authentication

### Token-Based with Interceptors

```typescript
import {
  PlatformClient,
  createAuthInterceptor,
} from 'trusted-platform-sdk';

const client = new PlatformClient({
  baseUrl: 'https://platform.example.com',
});

// Add auth interceptor
let authToken = '';

client.addRequestInterceptor(
  createAuthInterceptor(() => authToken)
);

// Login and store token
const loginResponse = await client.iam.authenticate({
  username: 'admin',
  password: 'password',
});
authToken = loginResponse.data!.accessToken;

// Subsequent requests include the token automatically
```

### Custom Token Refresh

```typescript
import { createAuthInterceptor } from 'trusted-platform-sdk';

let tokenData = {
  accessToken: '',
  refreshToken: '',
  expiresAt: 0,
};

async function getToken(): Promise<string> {
  // Check if token is expired
  if (Date.now() >= tokenData.expiresAt - 60000) {
    // Refresh token
    const response = await client.auth.refreshToken({
      refreshToken: tokenData.refreshToken,
    });
    tokenData = {
      accessToken: response.data!.accessToken!,
      refreshToken: response.data!.refreshToken ?? tokenData.refreshToken,
      expiresAt: response.data!.expiresAt! * 1000,
    };
  }
  return tokenData.accessToken;
}

client.addRequestInterceptor(createAuthInterceptor(getToken));
```

### Cookie-Based Authentication

```typescript
const client = new PlatformClient({
  baseUrl: 'https://platform.example.com',
  credentials: 'include', // Send cookies with requests
});
```

## Request/Response Interceptors

### Logging Interceptor

```typescript
import {
  createLoggingRequestInterceptor,
  createLoggingResponseInterceptor,
} from 'trusted-platform-sdk';

client.addRequestInterceptor(
  createLoggingRequestInterceptor(console.log)
);

client.addResponseInterceptor(
  createLoggingResponseInterceptor(console.log)
);
```

### Request ID Interceptor

```typescript
import { createRequestIdInterceptor } from 'trusted-platform-sdk';

client.addRequestInterceptor(createRequestIdInterceptor());
```

### Custom Interceptor

```typescript
// Request interceptor
const handle = client.addRequestInterceptor((config, context) => {
  console.log(`Request: ${context.method} ${context.url}`);
  return {
    ...config,
    headers: {
      ...config.headers,
      'X-Custom-Header': 'value',
    },
  };
});

// Remove interceptor later
handle.remove();

// Response interceptor
client.addResponseInterceptor((response, context) => {
  console.log(`Response: ${context.request.method} completed in ${context.durationMs}ms`);
  return response;
});

// Error interceptor
client.addErrorInterceptor((error, context) => {
  console.error(`Request failed: ${context.url}`, error);
  return error;
});
```

## Configuration Options

```typescript
interface ApiClientConfig {
  // Base URL for API requests
  baseUrl?: string;

  // Default headers
  headers?: Record<string, string>;

  // Credentials mode: 'omit' | 'same-origin' | 'include'
  credentials?: CredentialsMode;

  // Timeout configuration
  timeout?: {
    requestTimeoutMs?: number; // Default: 30000
    connectionTimeoutMs?: number; // Default: 10000
  };

  // Retry configuration
  retry?: {
    maxRetries?: number; // Default: 3
    initialDelayMs?: number; // Default: 1000
    maxDelayMs?: number; // Default: 30000
    backoffMultiplier?: number; // Default: 2
    retryableStatuses?: number[]; // Default: [408, 429, 500, 502, 503, 504]
    retryOnNetworkError?: boolean; // Default: true
  };

  // Throw on error (vs. returning error in response)
  throwOnError?: boolean; // Default: false

  // Custom fetch implementation (for SSR or testing)
  fetch?: typeof fetch;
}
```

## TypeScript Types

The SDK exports comprehensive TypeScript types:

```typescript
import type {
  // API Response types
  ApiResponse,
  ApiError,

  // Certificate types
  Certificate,
  CertificateRequest,
  CertificateProfile,

  // TPM types
  TPMInfo,
  SealRequest,
  SealResponse,
  QuoteRequest,
  QuoteResponse,

  // vTPM types
  VTPMInstance,
  VTPMBundle,
  CreateVTPMRequest,

  // IAM types
  User,
  Role,
  Permission,
  AuthResponse,

  // KMS types
  Key,
  EncryptRequest,
  EncryptResponse,

  // ... and more
} from 'trusted-platform-sdk';
```

## Error Handling

```typescript
const response = await client.ca.issueCertificate(request);

if (response.error) {
  // Handle specific error codes
  switch (response.error.code) {
    case 'INVALID_ARGUMENT':
      console.error('Invalid request:', response.error.message);
      break;
    case 'PERMISSION_DENIED':
      console.error('Access denied');
      break;
    case 'NOT_FOUND':
      console.error('Resource not found');
      break;
    case 'ALREADY_EXISTS':
      console.error('Resource already exists');
      break;
    default:
      console.error('Error:', response.error.message);
  }
  return;
}

// Success
console.log('Certificate:', response.data);
```

### Using utility functions

```typescript
import {
  isSuccessResponse,
  isErrorResponse,
  unwrapResponse,
} from 'trusted-platform-sdk';

const response = await client.ca.getCertificate(serial);

if (isSuccessResponse(response)) {
  console.log('Certificate:', response.data);
}

if (isErrorResponse(response)) {
  console.error('Error:', response.error);
}

// Unwrap or throw
try {
  const cert = unwrapResponse(response);
  console.log('Certificate:', cert);
} catch (error) {
  console.error('Failed:', error);
}
```

## Complete React Example

```tsx
import React, { useState } from 'react';
import {
  PlatformProvider,
  usePlatformClient,
  useApi,
  useMutation,
  useCA,
} from 'trusted-platform-sdk/react';

// Provider setup
function App() {
  return (
    <PlatformProvider
      config={{
        baseUrl: process.env.REACT_APP_API_URL,
        credentials: 'include',
        retry: { maxRetries: 3 },
      }}
    >
      <CertificateManager />
    </PlatformProvider>
  );
}

// Certificate management component
function CertificateManager() {
  const ca = useCA();
  const [commonName, setCommonName] = useState('');

  // Fetch certificates
  const { data, isLoading, error, refetch } = useApi(
    () => ca.listCertificates({ page: 1, pageSize: 20 }),
    [],
    { refetchInterval: 30000 }
  );

  // Issue certificate mutation
  const issueCert = useMutation(
    (req: { commonName: string }) =>
      ca.issueCertificate({
        subject: { commonName: req.commonName },
        validDays: 365,
      }),
    {
      onSuccess: () => {
        setCommonName('');
        refetch();
      },
    }
  );

  // Revoke certificate mutation
  const revokeCert = useMutation(
    (serial: string) =>
      ca.revokeCertificate({ serial, reason: 'unspecified' }),
    {
      onSuccess: () => refetch(),
    }
  );

  if (isLoading) return <div>Loading certificates...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <div>
      <h1>Certificate Manager</h1>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          issueCert.mutate({ commonName });
        }}
      >
        <input
          value={commonName}
          onChange={(e) => setCommonName(e.target.value)}
          placeholder="Common Name"
        />
        <button type="submit" disabled={issueCert.isLoading}>
          {issueCert.isLoading ? 'Issuing...' : 'Issue Certificate'}
        </button>
      </form>

      <table>
        <thead>
          <tr>
            <th>Serial</th>
            <th>Subject</th>
            <th>Expires</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {data?.certificates.map((cert) => (
            <tr key={cert.serial}>
              <td>{cert.serial}</td>
              <td>{cert.subject}</td>
              <td>{new Date(cert.notAfter).toLocaleDateString()}</td>
              <td>
                <button
                  onClick={() => revokeCert.mutate(cert.serial)}
                  disabled={revokeCert.isLoading}
                >
                  Revoke
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
```

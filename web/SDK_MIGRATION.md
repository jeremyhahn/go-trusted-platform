# SDK Migration Guide

This document describes the migration from local API modules (`web/src/lib/api/*.ts`) to the `trusted-platform-sdk` package.

## Overview

The web application has been updated to use the `trusted-platform-sdk` package instead of local API modules. This provides:
- Typed SDK with service-specific hooks
- Declarative data fetching with `useApi`
- Mutation support with `useMutation`
- Centralized client configuration

## Setup Complete

### 1. Package Dependency (DONE)

The SDK is added in `package.json`:
```json
{
  "dependencies": {
    "trusted-platform-sdk": "file:../sdk/javascript"
  }
}
```

### 2. Next.js Configuration (DONE)

Updated `next.config.mjs` to resolve the SDK:
- Added `transpilePackages: ["trusted-platform-sdk"]`
- Added webpack aliases for SDK subpath exports
- Added `turbopack: {}` for compatibility

### 3. Provider Setup (DONE)

Created `src/app/providers.tsx` with `PlatformProvider`:
```tsx
import { PlatformProvider } from "trusted-platform-sdk/react";

export function Providers({ children }) {
  return (
    <PlatformProvider
      config={{
        baseUrl: "/api",
        credentials: "include",
        // ... retry and timeout config
      }}
    >
      {children}
    </PlatformProvider>
  );
}
```

Updated `src/app/layout.tsx` to use the Providers component.

### 4. Hooks Re-export (DONE)

Updated `src/hooks/index.ts` to re-export SDK hooks:
```tsx
export {
  useApi,
  useMutation,
  usePlatformClient,
  usePlatform,
  useDevice,
  useCA,
  // ... all service hooks
} from 'trusted-platform-sdk/react';
```

## Migration Status

### Completed Migrations

| Page/Component | Service Hook | Status |
|----------------|--------------|--------|
| Health Page | `usePlatform` | Done |
| Devices Page | `useDevice` | Done |
| Certificates Page | `useCA` | Done |
| IAM Users | `useIAM` | Done |
| IAM Roles | `useIAM` | Done |
| IAM Policies | `useIAM` | Done |
| IAM Apps | `useIAM` | Done |
| IAM Tokens | `useIAM` | Done |
| KMS Keys | `useKMS` | Done |
| Tenant Page | `useTenant`, `useIAM` | Done |
| Compute VMs | `useCompute` | Done |
| Compute Containers | `useCompute` | Done |
| Attestation | `useAttestation` | Done |
| DNS Zones | `useDNS` | Done |
| SDN Networks | `useSDN` | Done |
| vTPM | `useVTPM` | Done |
| TPM Status | `useTPM` | Done |

### Files Still Using Local API

The following files may still use local API modules:
- `src/app/(dashboard)/ca/bundle/page.tsx`
- `src/app/(dashboard)/ca/crl/page.tsx`
- `src/app/(dashboard)/ca/requests/page.tsx`
- `src/app/(dashboard)/platform/config/page.tsx`
- `src/app/(dashboard)/platform/logs/page.tsx`
- `src/app/(dashboard)/storage/**/*.tsx`

## Migration Pattern

For each component that uses local API modules:

1. **Replace imports:**
   ```tsx
   // Before
   import { getSomething, createSomething } from '@/lib/api/service';

   // After
   import { useServiceName, useApi, useMutation } from '@/hooks';
   ```

2. **Get service instance:**
   ```tsx
   const service = useServiceName(); // e.g., useCA(), useDevice(), usePlatform()
   ```

3. **Replace fetch calls with useApi:**
   ```tsx
   const { data, isLoading, error, refetch } = useApi(
     () => service.listItems(),
     [dependencies],
     { onError: (err) => handleError(err) }
   );
   ```

4. **Replace mutations with useMutation:**
   ```tsx
   const createMutation = useMutation(
     (input) => service.create(input),
     {
       onSuccess: () => refetch(),
       onError: (err) => handleError(err),
     }
   );

   // Use: createMutation.mutate(data)
   ```

5. **Transform types if needed:**
   The SDK types may differ from local types. Create adapter functions:
   ```tsx
   const localItems = useMemo(() => {
     return (data?.items ?? []).map((item) => ({
       id: item.id,
       name: item.name,
       // ... map SDK fields to local type
     }));
   }, [data]);
   ```

## Examples

### Health Page
```tsx
import { usePlatform, useApi } from "@/hooks";

const platform = usePlatform();
const { data, isLoading, refetch } = useApi(
  () => platform.getHealth({ includeServices: true }),
  [],
  { refetchInterval: autoRefresh ? 30000 : undefined }
);
```

### Devices Page
```tsx
import { useDevice, useApi } from '@/hooks';

const deviceService = useDevice();
const { data, isLoading, refetch } = useApi(
  () => deviceService.listDevices({ page: 1, pageSize: 100 }),
  [filters]
);
```

### KMS Keys Page
```tsx
import { useKMS, useApi, useMutation } from '@/hooks';

const kms = useKMS();
const { data: keysData, refetch: loadKeys } = useApi(
  () => kms.listKeys(),
  []
);

const generateMutation = useMutation(
  async (data) => kms.generateKey({
    keySpec: { algorithm: data.algorithm, usage: data.usage },
    name: data.name,
  }),
  { onSuccess: () => loadKeys() }
);
```

### IAM with Tenant Context
```tsx
import { useIAM, useApi, useMutation } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';

const { tenantId } = useAuth();
const iam = useIAM();

const { data: usersData, refetch } = useApi(
  () => tenantId ? iam.listUsers({ tenantId }) : Promise.resolve({ data: null }),
  [tenantId]
);

const deleteUserMutation = useMutation(
  async (userId) => iam.deleteUser(tenantId, userId),
  { onSuccess: () => refetch() }
);
```

## Type Mapping Notes

- SDK `CertificateSummary.status` uses uppercase: `'VALID' | 'REVOKED' | 'EXPIRED'`
- Local `Certificate.status` uses lowercase: `'active' | 'revoked' | 'expired'`
- SDK `Device.id` is `number`, local `Device.id` is `string`
- SDK response types typically include the data wrapped in an object (e.g., `{ users: [...] }`)

## Build Notes

When building with Next.js 16:
- Use `npx next build --webpack` for production builds
- Turbopack (default) may have issues with local package resolution
- The webpack config in `next.config.mjs` handles SDK path resolution

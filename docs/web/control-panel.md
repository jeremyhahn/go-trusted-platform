# Control Panel UI

Professional control panel for go-trusted-platform exposing all 15 SDK services.

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | Next.js 16, React 19, TypeScript |
| Styling | Tailwind CSS v3, shadcn/ui |
| Data Tables | @tanstack/react-table |
| Forms | react-hook-form, zod |
| Icons | lucide-react |
| Theme | next-themes (dark/light/system) |

## Directory Structure

```
web/src/
├── app/
│   ├── (auth)/                   # Auth routes
│   └── (dashboard)/              # Dashboard layout group
│       ├── layout.tsx            # Sidebar + header
│       ├── dashboard/            # Home
│       ├── iam/                  # Users, roles, permissions, tokens
│       ├── tenant/               # Tenant management
│       ├── ca/                   # Certificate authority
│       ├── kms/                  # Key management
│       ├── devices/              # Devices, vTPM, IDevID
│       ├── attestation/          # TPM attestation
│       ├── compute/              # VMs, containers
│       ├── networking/           # SDN, DNS, overlays, gateway, PXE
│       └── platform/             # Health, config, logs
├── components/
│   ├── ui/                       # shadcn/ui components
│   ├── layout/                   # App sidebar, header, breadcrumbs
│   └── features/                 # Feature-specific components
├── hooks/                        # use-api, use-mutation, use-auth, use-toast
├── lib/api/                      # Service API clients
└── types/                        # TypeScript interfaces
```

## Services

| Service | Routes | Description |
|---------|--------|-------------|
| IAM | /iam/* | Users, roles, permissions, tokens |
| Tenant | /tenant/* | Multi-tenant management |
| CA | /ca/* | Certificate authority |
| KMS | /kms/* | Key management |
| Devices | /devices/* | Device registry, vTPM, IDevID |
| Attestation | /attestation/* | TPM attestation |
| Compute | /compute/* | VMs, containers |
| Networking | /networking/* | SDN, DNS, overlays, gateway, PXE |
| Platform | /platform/* | Health, config, logs |

## Components

### DataTable

```tsx
<DataTable
  columns={columns}
  data={data}
  searchKey="name"
  filterableColumns={[{ id: "status", title: "Status", options }]}
  pagination
  pageSize={25}
/>
```

### Page Pattern

```tsx
"use client";
import { useState, useEffect } from "react";
import { PageHeader } from "@/components/layout/page-header";
import { DataTable } from "@/components/ui/data-table";
import { getItems } from "@/lib/api/service";

export default function Page() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getItems().then(r => {
      if (r.data) setItems(r.data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Items" />
      <DataTable columns={columns} data={items} loading={loading} />
    </div>
  );
}
```

### API Client Pattern

```typescript
import { apiClient, ApiResponse } from "./client";

export async function getItems(): Promise<ApiResponse<Item[]>> {
  return apiClient.get<Item[]>("/api/service/items");
}
```

## Development

```bash
npm install     # Install dependencies
npm run dev     # Start dev server
npm run build   # Production build
npm run typecheck  # Type check
npm run lint    # Lint
```

## Dark Mode

Implemented via next-themes. Toggle in header. CSS variables in globals.css.

## Adding New Service

1. Types: `types/<service>.ts`
2. API client: `lib/api/<service>.ts`
3. Components: `components/features/<service>/`
4. Pages: `app/(dashboard)/<service>/`
5. Navigation: `components/layout/app-sidebar.tsx`

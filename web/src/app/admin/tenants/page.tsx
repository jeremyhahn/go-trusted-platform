"use client";

/**
 * Admin tenant list (#1673): ListTenants, CreateTenant, GetTenantByName and
 * DeleteTenant (behind a confirm dialog). Each row links to the detail page.
 */
import * as React from "react";
import Link from "next/link";
import { useApi, useTenant } from "@/hooks";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from "@/components/ui";
import { ConfirmDialog, errorText, type PendingAction } from "./confirm-dialog";
import { tenantStateName } from "./tenant-state";

/** The SDK's tenant record (the SDK root does not export the type). */
type Tenant = NonNullable<
  Awaited<ReturnType<ReturnType<typeof useTenant>["getTenant"]>>["data"]
>["tenant"];

function TenantRow({ tenant, onDelete }: { tenant: Tenant; onDelete: (t: Tenant) => void }) {
  return (
    <tr data-testid={`tenant-row-${tenant.id}`}>
      <td>
        <Link href={`/admin/tenants/${encodeURIComponent(tenant.id)}/`}>{tenant.name}</Link>
      </td>
      <td>{tenant.displayName ?? ""}</td>
      <td>
        <Badge variant={tenantStateName(tenant.state) === "ACTIVE" ? "default" : "secondary"}>
          {tenantStateName(tenant.state)}
        </Badge>
      </td>
      <td>
        <Button variant="destructive" size="sm" onClick={() => onDelete(tenant)}>
          Delete
        </Button>
      </td>
    </tr>
  );
}

/** Tenants per page of the All tenants table (the server's default limit). */
const PAGE_SIZE = 100;

export default function AdminTenantsPage() {
  const tenants = useTenant();
  const [offset, setOffset] = React.useState(0);
  const { data, isLoading, error, refetch } = useApi(
    () => tenants.listTenants({ limit: PAGE_SIZE, offset }),
    [offset],
  );
  const total = Number(data?.total ?? 0);
  const shown = data?.tenants?.length ?? 0;
  const first = shown > 0 ? offset + 1 : 0;
  const last = offset + shown;
  const [name, setName] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [found, setFound] = React.useState<Tenant | null>(null);
  const [status, setStatus] = React.useState("");
  const [pending, setPending] = React.useState<PendingAction | null>(null);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.createTenant({ name, displayName: displayName || undefined });
    if (res.success) {
      setStatus(`Created tenant ${name}`);
      setName("");
      setDisplayName("");
      await refetch();
    } else {
      setStatus(errorText(res, "Create failed"));
    }
  };

  const find = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.getTenantByName(search);
    if (res.success && res.data?.tenant) {
      setFound(res.data.tenant);
      setStatus("");
    } else {
      setFound(null);
      setStatus(errorText(res, `No tenant named ${search}`));
    }
  };

  const askDelete = (t: Tenant) =>
    setPending({
      title: `Delete tenant ${t.name}?`,
      description: "The tenant and its resources are removed. This cannot be undone.",
      confirmLabel: "Delete",
      run: async () => {
        const res = await tenants.deleteTenant(t.id);
        setStatus(res.success ? `Deleted tenant ${t.name}` : errorText(res, "Delete failed"));
        if (res.success) {
          if (found?.id === t.id) setFound(null);
          await refetch();
        }
      },
    });

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold">Tenants</h2>
      <p role="status" data-testid="action-result">
        {status}
      </p>

      <Card>
        <CardHeader>
          <CardTitle>Create tenant</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={create} className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="tenant-name">Name</Label>
              <Input id="tenant-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div>
              <Label htmlFor="tenant-display-name">Display name</Label>
              <Input
                id="tenant-display-name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <Button type="submit">Create</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Find by name</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={find} className="flex items-end gap-3">
            <div>
              <Label htmlFor="tenant-search">Tenant name</Label>
              <Input id="tenant-search" value={search} onChange={(e) => setSearch(e.target.value)} required />
            </div>
            <Button type="submit">Find</Button>
          </form>
          {found && (
            <table className="mt-4 w-full" data-testid="search-result">
              <tbody>
                <TenantRow tenant={found} onDelete={askDelete} />
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>All tenants</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p>Loading tenants...</p>
          ) : error ? (
            <p role="alert">Failed to load tenants: {error.message}</p>
          ) : (
            <table className="w-full" data-testid="tenant-list">
              <thead>
                <tr>
                  <th className="text-left">Name</th>
                  <th className="text-left">Display name</th>
                  <th className="text-left">State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(data?.tenants ?? []).map((t) => (
                  <TenantRow key={t.id} tenant={t} onDelete={askDelete} />
                ))}
              </tbody>
            </table>
          )}
          <div className="mt-4 flex items-center gap-3">
            <p data-testid="tenant-page-info">
              Showing {first}-{last} of {total}
            </p>
            <Button
              type="button"
              variant="outline"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </Button>
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog action={pending} onClose={() => setPending(null)} />
    </div>
  );
}

"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { useTenantDirectory } from "@/hooks/use-tenant-directory";

type Directory = ReturnType<typeof useTenantDirectory>;
type ListAnswer = Awaited<ReturnType<Directory["list"]>>;
type DirectoryTenant = NonNullable<ListAnswer["data"]>["tenants"][number];

interface Answer {
  success: boolean;
  error?: { message?: string };
}

/** The state as the server sends it ("TENANT_STATE_ACTIVE" or "ACTIVE"), without the enum prefix. */
function stateLabel(state: unknown): string {
  const text = state === undefined || state === null ? "UNSPECIFIED" : String(state);
  return text.replace(/^TENANT_STATE_/, "");
}

function stateVariant(label: string): "default" | "secondary" | "destructive" | "outline" {
  if (label === "ACTIVE") return "default";
  if (label === "SUSPENDED" || label === "DELETING") return "destructive";
  return "secondary";
}

function refusal(res: Answer | undefined, err?: unknown): string {
  if (err instanceof Error) return err.message;
  return res?.error?.message ?? "The control plane refused the request.";
}

/**
 * The tenant directory (#2067): lists the tenants through TenantService
 * ListTenants, creates one (CreateTenant), renames one (UpdateTenant) and
 * deletes one behind a confirm (DeleteTenant). Every write re-lists on
 * success; a refusal is a destructive toast with the server's message.
 */
export function TenantDirectoryCard() {
  const directory = useTenantDirectory();
  const { toast } = useToast();
  const [tenants, setTenants] = React.useState<DirectoryTenant[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [newName, setNewName] = React.useState("");
  const [newDisplayName, setNewDisplayName] = React.useState("");
  const [renaming, setRenaming] = React.useState<string | null>(null);
  const [renameValue, setRenameValue] = React.useState("");
  const [deleting, setDeleting] = React.useState<DirectoryTenant | null>(null);

  const refuse = React.useCallback(
    (title: string, description: string) => toast({ title, description, variant: "destructive" }),
    [toast]
  );

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await directory.list();
      if (res.success && res.data) {
        setTenants(res.data.tenants ?? []);
      } else {
        refuse("Tenant list failed", refusal(res));
      }
    } catch (err) {
      refuse("Tenant list failed", refusal(undefined, err));
    } finally {
      setLoading(false);
    }
  }, [directory, refuse]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function write(title: string, call: () => Promise<Answer>, done: () => void, success: string) {
    setBusy(true);
    try {
      const res = await call();
      if (!res.success) {
        refuse(title, refusal(res));
        return;
      }
      done();
      toast({ title: success, description: "The tenant directory is up to date." });
      await load();
    } catch (err) {
      refuse(title, refusal(undefined, err));
    } finally {
      setBusy(false);
    }
  }

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    const name = newName.trim();
    if (name === "") {
      refuse("Tenant not created", "A tenant name is required.");
      return;
    }
    await write(
      "Tenant create failed",
      () => directory.create(name, newDisplayName.trim()),
      () => {
        setNewName("");
        setNewDisplayName("");
      },
      "Tenant created"
    );
  }

  async function onRename(id: string) {
    await write(
      "Tenant rename failed",
      () => directory.rename(id, renameValue.trim()),
      () => setRenaming(null),
      "Tenant renamed"
    );
  }

  async function onDelete(target: DirectoryTenant) {
    await write("Tenant delete failed", () => directory.remove(target.id), () => setDeleting(null), "Tenant deleted");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Tenants</CardTitle>
        <CardDescription>Every tenant on this control plane (system tenant only)</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form noValidate onSubmit={onCreate} className="grid gap-4 md:grid-cols-3 md:items-end">
          <div className="space-y-2">
            <Label htmlFor="tenant-directory-new-name">New tenant name</Label>
            <Input
              id="tenant-directory-new-name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="tenant-directory-new-display-name">New tenant display name</Label>
            <Input
              id="tenant-directory-new-display-name"
              value={newDisplayName}
              onChange={(e) => setNewDisplayName(e.target.value)}
            />
          </div>
          <Button type="submit" disabled={busy}>
            Create
          </Button>
        </form>

        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-2">Name</th>
              <th className="py-2">Display name</th>
              <th className="py-2">State</th>
              <th className="py-2" />
            </tr>
          </thead>
          <tbody>
            {tenants.map((t) => {
              const label = stateLabel(t.state);
              return (
                <tr key={t.id} data-testid={`tenant-row-${t.id}`} className="border-t">
                  <td className="py-2 font-medium">{t.name}</td>
                  <td className="py-2">
                    {renaming === t.id ? (
                      <div className="flex items-center gap-2">
                        <Label htmlFor={`tenant-directory-rename-${t.id}`} className="sr-only">
                          {`Display name for ${t.name}`}
                        </Label>
                        <Input
                          id={`tenant-directory-rename-${t.id}`}
                          value={renameValue}
                          onChange={(e) => setRenameValue(e.target.value)}
                        />
                        <Button type="button" size="sm" disabled={busy} onClick={() => void onRename(t.id)}>
                          Save
                        </Button>
                      </div>
                    ) : (
                      t.displayName
                    )}
                  </td>
                  <td className="py-2">
                    <Badge variant={stateVariant(label)}>{label}</Badge>
                  </td>
                  <td className="py-2 text-right space-x-2">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        setRenaming(t.id);
                        setRenameValue(t.displayName ?? "");
                      }}
                    >
                      Rename
                    </Button>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => setDeleting(t)}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!loading && tenants.length === 0 && (
          <p className="text-sm text-muted-foreground">No tenants listed.</p>
        )}
      </CardContent>

      <Dialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{deleting ? `Delete ${deleting.name}?` : "Delete tenant?"}</DialogTitle>
            <DialogDescription>The control plane removes the tenant and its resources.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => deleting && void onDelete(deleting)}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

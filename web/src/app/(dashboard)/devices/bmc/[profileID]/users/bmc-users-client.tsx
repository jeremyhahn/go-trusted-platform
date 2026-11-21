"use client";

/**
 * BMC users and web certificate page (#1720): lists the user slots of
 * one BMC profile and drives CreateUser, DeleteUser, SetUserPassword,
 * SetUserPrivilege and ReplaceWebCertificate. Deleting a user and
 * replacing the certificate go through a confirm dialog.
 */

import { useState } from 'react';
import { useParams, usePathname } from 'next/navigation';
import { KeyRound, Plus, ShieldCheck, Trash2, UserCog } from 'lucide-react';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
} from '@/components/ui';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { useBMCUsers, bmcPrivilegeLabel, BMC_PRIVILEGES, useToast } from '@/hooks';
import type { BMCPrivilege, BMCUserSlot } from '@/hooks';

const selectClass =
  'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm';

type DialogKind = 'create' | 'password' | 'privilege' | 'delete' | 'cert' | null;

// Slots 0-2 are reserved by the BMC (0 and 1 anonymous/null, 2 the
// factory administrator); new accounts start at slot 3.
const FIRST_USER_SLOT = 3;

/** IPMI v2.0 caps a user password at 20 bytes (Set User Password). */
const IPMI_MAX_PASSWORD_BYTES = 20;

/**
 * Lowest slot from FIRST_USER_SLOT up that no listed user occupies.
 * IPMI CreateUser overwrites whatever account holds the slot, so the
 * caller must pick an unused one.
 */
function firstFreeSlot(users: BMCUserSlot[]): number {
  const taken = new Set(users.map((u) => u.slot));
  let slot = FIRST_USER_SLOT;
  while (taken.has(slot)) slot++;
  return slot;
}

export default function BMCUsersClient() {
  const params = useParams();
  const pathname = usePathname();
  const profileID = resolveDynamicId(params, pathname, 'bmc', 'profileID');
  const { toast } = useToast();
  const bmc = useBMCUsers(profileID);

  const [dialog, setDialog] = useState<DialogKind>(null);
  // The row a dialog acts on, tagged with the profile it was picked from:
  // after a profile change it no longer names a slot of this BMC.
  const [picked, setPicked] = useState<{ profileID: string; user: BMCUserSlot } | null>(null);
  const target = picked !== null && picked.profileID === profileID ? picked.user : null;
  const [busy, setBusy] = useState(false);

  const [createForm, setCreateForm] = useState({
    slot: String(FIRST_USER_SLOT),
    username: '',
    password: '',
    privilege: 'user' as BMCPrivilege,
    channel: '1',
    enabled: true,
  });
  const [password, setPassword] = useState('');
  const [privilege, setPrivilege] = useState<BMCPrivilege>('user');
  const [channel, setChannel] = useState('1');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [createError, setCreateError] = useState<string | null>(null);

  const open = (kind: DialogKind, user: BMCUserSlot | null = null) => {
    // CreateUser overwrites whatever holds the slot, so a free slot is only
    // known once the current profile's listing has succeeded.
    // Row actions likewise wait for it: until then the rows may be another
    // profile's.
    if ((kind === 'create' || user !== null) && !bmc.listed) return;
    setPicked(user ? { profileID, user } : null);
    if (kind === 'create') {
      setCreateForm((f) => ({ ...f, slot: String(firstFreeSlot(bmc.users)) }));
      setCreateError(null);
    }
    if (kind === 'password') setPassword('');
    if (kind === 'privilege' && user) {
      const name = bmcPrivilegeLabel(user.privilege);
      setPrivilege(name === 'unknown' ? 'user' : name);
      setChannel(String(user.channel || 1));
    }
    setDialog(kind);
  };

  const run = async (label: string, op: () => Promise<void>) => {
    setBusy(true);
    try {
      await op();
      toast({ title: 'Success', description: label });
      setDialog(null);
    } catch (e: unknown) {
      toast({
        title: 'Error',
        description: e instanceof Error ? e.message : String(e),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">BMC Users</h1>
          <p className="text-muted-foreground">
            User accounts and web certificate of BMC profile {profileID}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => open('cert')}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            Replace Web Certificate
          </Button>
          <Button onClick={() => open('create')} disabled={!bmc.listed}>
            <Plus className="mr-2 h-4 w-4" />
            Create User
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>User Slots</CardTitle>
          <CardDescription>Populated user slots reported by the BMC</CardDescription>
        </CardHeader>
        <CardContent>
          {bmc.error && (
            <p role="alert" className="mb-4 text-sm text-destructive">
              {bmc.error}
            </p>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Slot</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Privilege</TableHead>
                <TableHead>Channel</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bmc.isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    Loading users...
                  </TableCell>
                </TableRow>
              ) : bmc.users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No users found
                  </TableCell>
                </TableRow>
              ) : (
                bmc.users.map((u) => (
                  <TableRow key={u.slot} data-testid={`bmc-user-${u.slot}`}>
                    <TableCell className="font-mono">{u.slot}</TableCell>
                    <TableCell className="font-medium">{u.username}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{bmcPrivilegeLabel(u.privilege)}</Badge>
                    </TableCell>
                    <TableCell>{u.channel}</TableCell>
                    <TableCell>{u.enabled ? 'Yes' : 'No'}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Set password of ${u.username}`}
                          onClick={() => open('password', u)}
                          disabled={!bmc.listed}
                        >
                          <KeyRound className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Set privilege of ${u.username}`}
                          onClick={() => open('privilege', u)}
                          disabled={!bmc.listed}
                        >
                          <UserCog className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Delete ${u.username}`}
                          onClick={() => open('delete', u)}
                          disabled={!bmc.listed}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={dialog === 'create'} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create User</DialogTitle>
            <DialogDescription>Provision a user account in a BMC slot.</DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!bmc.listed) {
                setCreateError('The user list has not loaded; reload it before creating a user.');
                return;
              }
              const slot = Number(createForm.slot);
              const holder = bmc.users.find((u) => u.slot === slot);
              if (holder) {
                setCreateError(
                  `Slot ${slot} is already held by ${holder.username}; pick a free slot.`
                );
                return;
              }
              if (new TextEncoder().encode(createForm.password).length > IPMI_MAX_PASSWORD_BYTES) {
                setCreateError('The password is longer than 20 bytes (UTF-8), the IPMI limit; shorten it.');
                return;
              }
              setCreateError(null);
              void run('User created', () =>
                bmc.createUser({
                  slot,
                  username: createForm.username,
                  password: createForm.password,
                  privilege: createForm.privilege,
                  enabled: createForm.enabled,
                  channel: Number(createForm.channel),
                })
              );
            }}
          >
            <div>
              <Label htmlFor="bmc-create-slot">Slot</Label>
              <Input
                id="bmc-create-slot"
                type="number"
                min={0}
                value={createForm.slot}
                onChange={(e) => {
                  setCreateForm({ ...createForm, slot: e.target.value });
                  setCreateError(null);
                }}
                required
              />
              {createError && (
                <p role="alert" className="mt-1 text-sm text-destructive" data-testid="bmc-create-slot-error">
                  {createError}
                </p>
              )}
            </div>
            <div>
              <Label htmlFor="bmc-create-username">Username</Label>
              <Input
                id="bmc-create-username"
                value={createForm.username}
                onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
                required
              />
            </div>
            <div>
              <Label htmlFor="bmc-create-password">Password</Label>
              <Input
                id="bmc-create-password"
                type="password"
                value={createForm.password}
                onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
                required
              />
              <p className="mt-1 text-xs text-muted-foreground">At most 20 bytes (IPMI limit).</p>
            </div>
            <div>
              <Label htmlFor="bmc-create-privilege">Privilege</Label>
              <select
                id="bmc-create-privilege"
                className={selectClass}
                value={createForm.privilege}
                onChange={(e) =>
                  setCreateForm({ ...createForm, privilege: e.target.value as BMCPrivilege })
                }
              >
                {BMC_PRIVILEGES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label htmlFor="bmc-create-channel">Channel</Label>
              <Input
                id="bmc-create-channel"
                type="number"
                min={0}
                value={createForm.channel}
                onChange={(e) => setCreateForm({ ...createForm, channel: e.target.value })}
                required
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                id="bmc-create-enabled"
                type="checkbox"
                checked={createForm.enabled}
                onChange={(e) => setCreateForm({ ...createForm, enabled: e.target.checked })}
              />
              <Label htmlFor="bmc-create-enabled">Enabled</Label>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy || !bmc.listed}>
                Create
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={dialog === 'password'} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set Password</DialogTitle>
            <DialogDescription>New password for {target?.username}.</DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!target) return;
              void run('Password updated', () => bmc.setUserPassword(target.slot, password));
            }}
          >
            <div>
              <Label htmlFor="bmc-new-password">New password</Label>
              <Input
                id="bmc-new-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy}>
                Set Password
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={dialog === 'privilege'} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set Privilege</DialogTitle>
            <DialogDescription>Channel privilege for {target?.username}.</DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!target) return;
              void run('Privilege updated', () =>
                bmc.setUserPrivilege(target.slot, privilege, Number(channel))
              );
            }}
          >
            <div>
              <Label htmlFor="bmc-privilege">Privilege</Label>
              <select
                id="bmc-privilege"
                className={selectClass}
                value={privilege}
                onChange={(e) => setPrivilege(e.target.value as BMCPrivilege)}
              >
                {BMC_PRIVILEGES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label htmlFor="bmc-privilege-channel">Channel</Label>
              <Input
                id="bmc-privilege-channel"
                type="number"
                min={0}
                value={channel}
                onChange={(e) => setChannel(e.target.value)}
                required
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy}>
                Set Privilege
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={dialog === 'delete'} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>
              Delete {target?.username} from slot {target?.slot}? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDialog(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => {
                if (!target) return;
                void run('User deleted', () => bmc.deleteUser(target.slot));
              }}
            >
              Confirm Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={dialog === 'cert'} onOpenChange={(o) => !o && setDialog(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Replace Web Certificate</DialogTitle>
            <DialogDescription>
              Replaces the BMC HTTPS certificate and key. Sessions on the old certificate end.
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void run('Web certificate replaced', () => bmc.replaceWebCertificate(certPem, keyPem));
            }}
          >
            <div>
              <Label htmlFor="bmc-cert-pem">Certificate (PEM)</Label>
              <Textarea
                id="bmc-cert-pem"
                rows={6}
                className="font-mono text-xs"
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
                required
              />
            </div>
            <div>
              <Label htmlFor="bmc-key-pem">Private key (PEM)</Label>
              <Textarea
                id="bmc-key-pem"
                rows={6}
                className="font-mono text-xs"
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
                required
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setDialog(null)}>
                Cancel
              </Button>
              <Button type="submit" variant="destructive" disabled={busy}>
                Confirm Replace
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

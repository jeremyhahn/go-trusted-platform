'use client';

/**
 * BMCAccountsCard — the user accounts of one BMC profile (#2040).
 *
 * It runs the five user operations served under
 * `/api/v1/bmc/{profileID}/users` (ListUsers, CreateUser, DeleteUser,
 * SetUserPassword, SetUserPrivilege) through useBMCAccounts. ListUsers answers
 * the privilege as the IPMI number; the writes take it as a name. Delete asks
 * first. A password is never shown, and it is not kept after the call. Every
 * refusal is shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { Gated } from '@/components/features/capabilities/gated';
import {
  bmcPrivilegeName,
  useBMCAccounts,
  type BMCPrivilegeName,
  type BMCUser,
} from '@/hooks/use-bmc-accounts';

export const BMC_PRIVILEGE_CHOICES: BMCPrivilegeName[] = [
  'administrator',
  'operator',
  'user',
  'callback',
  'no-access',
];

export interface BMCAccountsCardProps {
  profileID: string;
}

// The users routes as the server names them; each write control is gated on its own.
const CREATE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/users';
const DELETE_OP = 'DELETE /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}';
const PASSWORD_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password';
const PRIVILEGE_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege';

const SELECT_CLASS =
  'h-9 rounded-md border border-input bg-background px-2 text-sm disabled:cursor-not-allowed disabled:opacity-50';

function currentChoice(level: number): BMCPrivilegeName {
  const name = bmcPrivilegeName(level);
  return (BMC_PRIVILEGE_CHOICES as string[]).includes(name) ? (name as BMCPrivilegeName) : 'user';
}

interface UserTarget {
  slot: number;
  username: string;
}

export function BMCAccountsCard({ profileID }: BMCAccountsCardProps) {
  const accounts = useBMCAccounts(profileID);
  const { toast } = useToast();
  const [users, setUsers] = useState<BMCUser[]>([]);
  const [choices, setChoices] = useState<Record<number, BMCPrivilegeName>>({});
  const [busy, setBusy] = useState(false);
  // The list must have loaded before Create is offered, so a used slot is known.
  const [loaded, setLoaded] = useState(false);

  const [slot, setSlot] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [privilege, setPrivilege] = useState<BMCPrivilegeName>('user');

  const [passwordTarget, setPasswordTarget] = useState<UserTarget | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<UserTarget | null>(null);

  const failed = useCallback(
    (title: string, message?: string) =>
      toast({ title, description: message ?? 'Unknown error', variant: 'destructive' }),
    [toast]
  );

  // A rejected read (the SDK refuses an invalid profile ID before any request)
  // is the card's error state, never an unhandled rejection.
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await accounts.listUsers();
      if (res.success) {
        setUsers(res.data ?? []);
        setLoaded(true);
        setLoadError(null);
      } else {
        failed('BMC users unavailable', res.error?.message);
      }
    } catch (err) {
      setLoaded(false);
      setLoadError(err instanceof Error ? err.message : String(err));
    }
  }, [accounts, failed]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const choiceFor = (u: BMCUser) => choices[u.slot] ?? currentChoice(u.privilege);

  const handleSetPrivilege = async (u: BMCUser) => {
    const choice = choiceFor(u);
    setBusy(true);
    try {
      const res = await accounts.setPrivilege(u.slot, choice);
      if (res.success) {
        toast({ title: 'Privilege set', description: `${u.username} is now ${choice}` });
        await reload();
      } else {
        failed('Set privilege failed', res.error?.message);
      }
    } finally {
      setBusy(false);
    }
  };

  const slotTaken = slot !== '' && users.some((u) => u.slot === Number(slot));

  const handleCreate = async () => {
    setBusy(true);
    try {
      const res = await accounts.createUser({ slot: Number(slot), username, password, privilege });
      if (res.success && res.data) {
        toast({ title: 'User created', description: `${res.data.username} in slot ${res.data.slot}` });
        setSlot('');
        setUsername('');
        await reload();
      } else {
        failed('Create user failed', res.error?.message);
      }
    } finally {
      // The password never stays in the form, after a refusal either.
      setPassword('');
      setBusy(false);
    }
  };

  const closePasswordDialog = () => {
    setPasswordTarget(null);
    setNewPassword('');
  };

  const handleSavePassword = async () => {
    if (!passwordTarget) return;
    const target = passwordTarget;
    const pw = newPassword;
    setBusy(true);
    try {
      const res = await accounts.setPassword(target.slot, pw);
      if (res.success) {
        toast({ title: 'Password set', description: target.username });
      } else {
        failed('Set password failed', res.error?.message);
      }
    } finally {
      closePasswordDialog();
      setBusy(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    const target = deleteTarget;
    setBusy(true);
    try {
      const res = await accounts.deleteUser(target.slot);
      if (res.success) {
        toast({ title: 'User deleted', description: target.username });
        setDeleteTarget(null);
        await reload();
      } else {
        failed('Delete user failed', res.error?.message);
        setDeleteTarget(null);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="bmc-accounts-card">
      <CardHeader>
        <CardTitle>BMC users</CardTitle>
        <CardDescription>
          The user accounts on BMC profile {profileID}. Passwords are never shown.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {loadError !== null && (
          <p role="alert" data-testid="bmc-accounts-error" className="text-sm text-destructive">
            BMC users unavailable: {loadError}
          </p>
        )}
        {users.length === 0 ? (
          <p className="text-sm text-muted-foreground">No BMC users</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Slot</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Privilege</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow key={u.slot} data-testid={`bmc-user-${u.slot}`}>
                  <TableCell>{u.slot}</TableCell>
                  <TableCell>{u.username}</TableCell>
                  <TableCell>{u.enabled ? 'Yes' : 'No'}</TableCell>
                  <TableCell>{bmcPrivilegeName(u.privilege)}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-2">
                      <select
                        aria-label={`Privilege for ${u.username}`}
                        className={SELECT_CLASS}
                        value={choiceFor(u)}
                        disabled={busy}
                        onChange={(e) =>
                          setChoices((prev) => ({ ...prev, [u.slot]: e.target.value as BMCPrivilegeName }))
                        }
                      >
                        {BMC_PRIVILEGE_CHOICES.map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>
                      <Gated op={PRIVILEGE_OP}>
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={`Set privilege for ${u.username}`}
                          disabled={busy}
                          onClick={() => void handleSetPrivilege(u)}
                        >
                          Set privilege
                        </Button>
                      </Gated>
                      <Gated op={PASSWORD_OP}>
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={`Set password for ${u.username}`}
                          disabled={busy}
                          onClick={() => {
                            setNewPassword('');
                            setPasswordTarget({ slot: u.slot, username: u.username });
                          }}
                        >
                          Set password
                        </Button>
                      </Gated>
                      <Gated op={DELETE_OP}>
                        <Button
                          size="sm"
                          variant="destructive"
                          aria-label={`Delete ${u.username}`}
                          disabled={busy}
                          onClick={() => setDeleteTarget({ slot: u.slot, username: u.username })}
                        >
                          Delete
                        </Button>
                      </Gated>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <div className="flex flex-wrap items-end gap-2">
          <Input
            aria-label="Slot"
            type="number"
            placeholder="Slot"
            className="w-24"
            value={slot}
            onChange={(e) => setSlot(e.target.value)}
          />
          {slotTaken && <p className="text-sm text-destructive">Slot {slot} is in use</p>}
          <Input
            aria-label="Username"
            placeholder="Username"
            className="w-40"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            aria-label="Password"
            type="password"
            placeholder="Password"
            className="w-40"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <select
            aria-label="Privilege"
            className={SELECT_CLASS}
            value={privilege}
            onChange={(e) => setPrivilege(e.target.value as BMCPrivilegeName)}
          >
            {BMC_PRIVILEGE_CHOICES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <Gated op={CREATE_OP}>
            <Button
              disabled={busy || !loaded || slotTaken || !slot || !username.trim() || !password}
              onClick={() => void handleCreate()}
            >
              Create user
            </Button>
          </Gated>
        </div>
      </CardContent>

      <Dialog open={passwordTarget !== null} onOpenChange={(open) => !open && closePasswordDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set the password of {passwordTarget?.username}?</DialogTitle>
            <DialogDescription>
              The new password goes to BMC slot {passwordTarget?.slot}; it is not shown or kept.
            </DialogDescription>
          </DialogHeader>
          <Input
            aria-label="New password"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={closePasswordDialog} disabled={busy}>
              Cancel
            </Button>
            <Gated op={PASSWORD_OP}>
              <Button onClick={() => void handleSavePassword()} disabled={busy || !newPassword}>
                Save password
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {deleteTarget?.username}?</DialogTitle>
            <DialogDescription>
              This removes BMC slot {deleteTarget?.slot} on profile {profileID}.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={busy}>
              Cancel
            </Button>
            <Gated op={DELETE_OP}>
              <Button variant="destructive" onClick={() => void handleDelete()} disabled={busy}>
                Confirm
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

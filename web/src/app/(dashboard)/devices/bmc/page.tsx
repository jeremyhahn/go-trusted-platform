"use client";

/**
 * BMC entry page (#1720): pick a BMC profile ID and open its users and
 * web certificate page.
 */

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from '@/components/ui';

export default function BMCPage() {
  const router = useRouter();
  const [profileID, setProfileID] = useState('');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">BMC</h1>
        <p className="text-muted-foreground">Baseboard management controller accounts and certificates</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Open a BMC profile</CardTitle>
          <CardDescription>Enter the numeric ID of the BMC profile to manage.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              const id = profileID.trim();
              if (id) router.push(`/devices/bmc/${encodeURIComponent(id)}/users`);
            }}
          >
            <div className="flex-1">
              <Label htmlFor="bmc-profile-id">Profile ID</Label>
              <Input
                id="bmc-profile-id"
                inputMode="numeric"
                value={profileID}
                onChange={(e) => setProfileID(e.target.value)}
                required
              />
            </div>
            <Button type="submit">Open Users</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

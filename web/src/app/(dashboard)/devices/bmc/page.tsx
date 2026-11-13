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
"use client";

/**
 * BMC landing page: opens the power, boot device, virtual media, sensors
 * and provision page of one BMC profile (#1736).
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

  const router = useRouter();
  const [profileID, setProfileID] = useState("");
  const [error, setError] = useState<string | null>(null);

  const open = (e: React.FormEvent) => {
    e.preventDefault();
    const id = profileID.trim();
    if (id && !/^[0-9]+$/.test(id)) {
      setError("The BMC profile ID is a number, such as 1.");
      return;
    }
    setError(null);
    if (id) {
      router.push(`/devices/bmc/${encodeURIComponent(id)}/`);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">BMC</h1>
        <p className="text-muted-foreground">Out-of-band power, boot, media and provisioning</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Open a BMC profile
          </CardTitle>
          <CardDescription>Enter the numeric ID of the device profile whose BMC to manage</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={open} className="flex items-end gap-2">
            <div className="flex-1">
              <Label htmlFor="bmc-profile-id">BMC profile ID</Label>
              <Input
                id="bmc-profile-id"
                value={profileID}
                onChange={(e) => {
                  setProfileID(e.target.value);
                  setError(null);
                }}
                placeholder="1"
                inputMode="numeric"
              />
            </div>
            <Button type="submit">Open</Button>
          </form>
          {error && (
            <p data-testid="bmc-profile-id-error" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

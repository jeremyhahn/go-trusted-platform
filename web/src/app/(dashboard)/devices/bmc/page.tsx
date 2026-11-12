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

export default function BMCPage() {
  const router = useRouter();
  const [profileID, setProfileID] = useState("");

  const open = (e: React.FormEvent) => {
    e.preventDefault();
    const id = profileID.trim();
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
          <CardDescription>Enter the ID of the BMC profile to manage</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={open} className="flex items-end gap-2">
            <div className="flex-1">
              <Label htmlFor="bmc-profile-id">BMC profile ID</Label>
              <Input
                id="bmc-profile-id"
                value={profileID}
                onChange={(e) => setProfileID(e.target.value)}
                placeholder="r640-01"
              />
            </div>
            <Button type="submit">Open</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

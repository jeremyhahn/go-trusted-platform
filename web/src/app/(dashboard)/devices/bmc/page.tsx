'use client';

/**
 * BMC Page
 * One BMC profile's system, power, boot and media, provisioning, sensor and
 * web certificate cards. Each card gates its write controls on the server's
 * capabilities.
 */

import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { BMCSystemCard } from '@/components/features/bmc/bmc-system-card';
import { BMCPowerCard } from '@/components/features/bmc/bmc-power-card';
import { BMCBootMediaCard } from '@/components/features/bmc/bmc-boot-media-card';
import { BMCProvisionCard } from '@/components/features/bmc/bmc-provision-card';
import { BMCSensorsCard } from '@/components/features/bmc/bmc-sensors-card';
import { BMCWebCertCard } from '@/components/features/bmc/bmc-web-cert-card';

export default function BMCPage() {
  const [profileID, setProfileID] = useState('');
  const id = profileID.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">BMC</h1>
        <p className="text-muted-foreground">Out-of-band management of a device through its BMC profile</p>
      </div>

      <div className="flex max-w-sm flex-col gap-2">
        <Label htmlFor="bmc-profile-id">BMC profile ID</Label>
        <Input
          id="bmc-profile-id"
          inputMode="numeric"
          placeholder="1"
          value={profileID}
          onChange={(e) => setProfileID(e.target.value)}
        />
      </div>

      {id !== '' && (
        <div key={id} className="grid gap-6 lg:grid-cols-2">
          <BMCSystemCard profileID={id} />
          <BMCPowerCard profileID={id} />
          <BMCBootMediaCard profileID={id} />
          <BMCProvisionCard profileID={id} />
          <BMCSensorsCard profileID={id} />
          <BMCWebCertCard profileID={id} />
        </div>
      )}
    </div>
  );
}

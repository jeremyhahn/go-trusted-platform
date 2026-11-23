'use client';

import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { BMCCertCard } from '@/components/features/bmc/bmc-cert-card';
import { BMCAccountsCard } from '@/components/features/bmc/bmc-accounts-card';

// The BMC certificate and users of one BMC profile (#2040). The cards remount
// when the profile ID changes, so no state of one profile shows on another.
export default function BMCAccountsPage() {
  const [profileID, setProfileID] = useState('');
  const id = profileID.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">BMC certificate and users</h1>
        <p className="text-muted-foreground">
          Enrol, restore and replace the BMC certificate, and manage the BMC user accounts of one BMC profile
        </p>
      </div>

      <div className="max-w-xs space-y-2">
        <Label htmlFor="bmc-accounts-profile-id">BMC profile ID</Label>
        <Input
          id="bmc-accounts-profile-id"
          inputMode="numeric"
          placeholder="1"
          value={profileID}
          onChange={(e) => setProfileID(e.target.value)}
        />
      </div>

      {id !== '' && (
        <div key={id} className="grid gap-6 lg:grid-cols-2">
          <BMCCertCard profileID={id} />
          <BMCAccountsCard profileID={id} />
        </div>
      )}
    </div>
  );
}

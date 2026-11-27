'use client';

import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { BMCCertCard } from '@/components/features/bmc/bmc-cert-card';
import { BMCAccountsCard } from '@/components/features/bmc/bmc-accounts-card';

// The BMC certificate and users of one BMC profile (#2040). The cards remount
// when the profile ID changes, so no state of one profile shows on another.
const UINT64_MAX_DECIMAL = '18446744073709551615';

// validBMCProfileID is the server's {profileID} rule: a decimal uint64 with no
// leading zero. The SDK refuses any other ID, so no card mounts for one.
function validBMCProfileID(id: string): boolean {
  if (!/^(0|[1-9][0-9]{0,19})$/.test(id)) return false;
  return id.length < UINT64_MAX_DECIMAL.length || id <= UINT64_MAX_DECIMAL;
}

export default function BMCAccountsPage() {
  const [profileID, setProfileID] = useState('');
  const id = profileID.trim();
  const valid = id !== '' && validBMCProfileID(id);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">BMC certificate and users</h1>
        <p className="text-muted-foreground">
          Restore the BMC factory certificate, and manage the BMC user accounts of one BMC profile
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

      {id !== '' && !valid && (
        <p role="alert" className="text-sm text-destructive">
          The BMC profile ID must be a decimal number (0 to {UINT64_MAX_DECIMAL}) with no leading zero
        </p>
      )}

      {valid && (
        <div key={id} className="grid gap-6 lg:grid-cols-2">
          <BMCCertCard profileID={id} />
          <BMCAccountsCard profileID={id} />
        </div>
      )}
    </div>
  );
}

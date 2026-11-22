'use client';

/**
 * Device Profiles Management Page
 * Display and manage device profiles with network phase configurations
 */

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Plus,
  Filter,
  RefreshCw,
  MoreHorizontal,
  Eye,
  Pencil,
  Trash2,
  Copy,
  Settings2,
  Layers,
  Network,
  Shield,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast, useApi, useDevice, useMutation } from '@/hooks';
import type { DeviceProfile, DeviceRole } from 'trusted-platform-sdk';
import {
  ASSIGNABLE_DEVICE_ROLES,
  DEVICE_ROLES,
  deviceRoleLabel,
  toDeviceRole,
} from '@/lib/device-role';
import { networkPhaseRows } from '@/lib/device-profile-networks';
import { baselineAge, baselineRegisters, baselineSourceLabel } from '@/lib/pcr-baseline';

// ============================================================================
// Types
// ============================================================================

interface ProfileFilters {
  role?: DeviceRole;
  search?: string;
}

interface ProfileStats {
  total: number;
  byRole: Partial<Record<DeviceRole, number>>;
}

// ============================================================================
// Helper Functions
// ============================================================================

function computeStats(profiles: DeviceProfile[]): ProfileStats {
  const byRole: Partial<Record<DeviceRole, number>> = {};
  profiles.forEach((profile) => {
    const role = profile.role || 'unknown';
    byRole[role] = (byRole[role] || 0) + 1;
  });

  return {
    total: profiles.length,
    byRole,
  };
}

function getRoleBadge(role: DeviceRole) {
  return <Badge variant="outline">{deviceRoleLabel(role)}</Badge>;
}

/**
 * The Networks column. Reads the profile's open-keyed `networks` map and marks
 * each entry with the lifecycle roles its key is selected for, so which phase
 * is active is visible rather than inferred from a key's spelling.
 */
function ProfileNetworksCell({ profile }: { profile: DeviceProfile }) {
  const rows = networkPhaseRows(profile);
  if (rows.length === 0) {
    return <span className="text-xs text-muted-foreground">No networks</span>;
  }
  return (
    <div className="flex flex-col gap-1 text-xs">
      {rows.map((row) => (
        <div key={row.name} className="flex items-center gap-1">
          <Badge variant="outline" className="text-xs">
            {row.name}
            {row.config.vlan ? ` (VLAN ${row.config.vlan})` : ''}
          </Badge>
          {row.roles.length > 0 && (
            <span className="text-muted-foreground">{row.roles.join(', ')}</span>
          )}
        </div>
      ))}
    </div>
  );
}

/**
 * The PCR Baseline column: which kind of baseline devices on this profile are
 * verified against, how old it is, which registers it covers and, for a
 * trust-on-first-use baseline, the device whose quote seeded it (#404).
 */
function ProfileBaselineCell({ profile }: { profile: DeviceProfile }) {
  const baseline = profile.pcr_baseline;
  if (!baseline) {
    return (
      <span
        className="text-xs text-muted-foreground"
        title="No baseline yet: the first fully verified quote on this profile records one"
      >
        No baseline
      </span>
    );
  }
  return (
    <div className="flex flex-col gap-1 text-xs">
      <div className="flex items-center gap-1">
        <Badge variant={baseline.source === 'signed' ? 'default' : 'outline'} className="text-xs">
          {baselineSourceLabel(baseline.source)}
        </Badge>
        <span className="text-muted-foreground" title={baseline.recorded_at}>
          {baselineAge(baseline.recorded_at)} old
        </span>
      </div>
      <span className="text-muted-foreground">{baselineRegisters(baseline)}</span>
      {baseline.recorded_from_device_id && (
        <span className="text-muted-foreground">
          seeded by device{' '}
          <Link href={`/devices/${baseline.recorded_from_device_id}`} className="underline">
            {baseline.recorded_from_device_id}
          </Link>
        </span>
      )}
    </div>
  );
}

function formatDate(dateString: string | null | undefined) {
  if (!dateString) return '—';
  const d = new Date(dateString);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

// ============================================================================
// Main Component
// ============================================================================

export default function DeviceProfilesPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [filters, setFilters] = useState<ProfileFilters>({});
  const deviceService = useDevice();

  // Fetch profiles using SDK
  const {
    data: profilesData,
    isLoading,
    error: profilesError,
    refetch: refetchProfiles,
  } = useApi(
    () => deviceService.listProfiles(),
    [],
    {
      onError: (err) => {
        toast({
          title: 'Error loading profiles',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // The registered total, from GET /device/profiles/count (#2048). The list
  // above loads one server page; the count tells the operator when it is cut
  // off. A refused count hides the line; the list still renders. useApi keeps
  // the last data on error, so a failed refresh must hide it too (#2185 Codex).
  const { data: countResponse, error: countError, refetch: refetchCount } = useApi(
    () => deviceService.countProfiles(),
    []
  );
  const registeredTotal = countError ? undefined : countResponse?.count;

  // Find one profile by serial or MAC address (FindProfileBySerial and
  // FindProfileByMACAddress, #2048). A 404 means no profile matches; any
  // other refusal shows the server's message. Editing the query clears the
  // old answer.
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookup, setLookup] = useState<
    | { kind: 'found'; profile: DeviceProfile }
    | { kind: 'none'; query: string }
    | { kind: 'error'; message: string }
    | null
  >(null);
  const lookupDisabled = lookupBusy || lookupQuery.trim() === '';

  const findProfile = async (by: 'serial' | 'mac') => {
    const q = lookupQuery.trim();
    if (q === '') return;
    setLookupBusy(true);
    try {
      const res =
        by === 'serial'
          ? await deviceService.findProfileBySerial(q)
          : await deviceService.findProfileByMACAddress(q);
      if (res.error?.status === 404) {
        setLookup({ kind: 'none', query: q });
      } else if (res.error) {
        setLookup({ kind: 'error', message: res.error.message });
      } else {
        // The server's FindProfileBySerial and FindProfileByMAC handlers
        // answer the profile itself, while the SDK types the response as
        // { profile?: DeviceProfile }; accept both shapes.
        const payload = res.data as unknown as
          | { profile?: DeviceProfile }
          | (DeviceProfile & { profile?: undefined })
          | undefined;
        let profile: DeviceProfile | undefined;
        if (payload && 'profile' in payload && payload.profile) {
          profile = payload.profile;
        } else if (payload && 'id' in payload && payload.id) {
          profile = payload as DeviceProfile;
        }
        setLookup(profile ? { kind: 'found', profile } : { kind: 'none', query: q });
      }
    } finally {
      setLookupBusy(false);
    }
  };

  const profiles: DeviceProfile[] = useMemo(() => {
    if (!profilesData?.profiles) return [];
    return profilesData.profiles;
  }, [profilesData]);
  const loadedCount = profiles.length;

  // Filtered profiles
  const filteredProfiles = useMemo(() => {
    return profiles.filter((profile) => {
      if (filters.role && profile.role !== filters.role) return false;
      if (filters.search) {
        const search = filters.search.toLowerCase();
        return (
          profile.name.toLowerCase().includes(search) ||
          profile.model?.toLowerCase().includes(search) ||
          profile.id.toString().includes(search)
        );
      }
      return true;
    });
  }, [profiles, filters]);

  // Statistics
  const stats = useMemo(() => computeStats(profiles), [profiles]);

  // Handlers
  const handleFilterChange = (key: keyof ProfileFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  // Delete profile mutation
  const deleteProfileMutation = useMutation(
    async (profileId: string) => {
      return deviceService.deleteProfile(profileId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Profile deleted',
          description: 'The profile has been deleted successfully',
          variant: 'success',
        });
        refetchProfiles();
        refetchCount();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting profile',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Create profile mutation
  const createProfileMutation = useMutation(
    async (data: { name: string; model?: string; role: DeviceRole }) => {
      return deviceService.createProfile({
        profile: {
          name: data.name,
          model: data.model,
          role: data.role,
        },
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Profile created',
          description: 'The profile has been created successfully',
          variant: 'success',
        });
        refetchProfiles();
        refetchCount();
        setIsCreateDialogOpen(false);
      },
      onError: (error) => {
        toast({
          title: 'Error creating profile',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleViewProfile = (profile: DeviceProfile) => {
    router.push(`/devices/profiles/${profile.id}`);
  };

  const handleEditProfile = (profile: DeviceProfile) => {
    router.push(`/devices/profiles/${profile.id}/edit`);
  };

  const handleDuplicateProfile = async (profile: DeviceProfile) => {
    try {
      await createProfileMutation.mutateAsync({
        name: `${profile.name} (Copy)`,
        model: profile.model,
        role: profile.role,
      });
    } catch {
      // Error handling is done in the mutation
    }
  };

  const handleDeleteProfile = async (profile: DeviceProfile) => {
    if (!confirm(`Are you sure you want to delete "${profile.name}"?`)) {
      return;
    }

    deleteProfileMutation.mutate(profile.id);
  };

  const handleCreateProfile = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    let role: DeviceRole;
    try {
      role = toDeviceRole(formData.get('role'));
    } catch (error) {
      toast({
        title: 'Error creating profile',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
      return;
    }

    try {
      await createProfileMutation.mutateAsync({
        name: formData.get('name') as string,
        model: formData.get('model') as string || undefined,
        role,
      });
    } catch {
      // Error handling is done in the mutation
    }
  };

  // Show error state
  if (profilesError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Profiles</AlertTitle>
          <AlertDescription>
            {profilesError.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetchProfiles()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Device Profiles</h1>
          <p className="text-muted-foreground">
            Manage device configuration profiles with network phase settings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => { refetchProfiles(); refetchCount(); }} disabled={isLoading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Profile
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create Device Profile</DialogTitle>
                <DialogDescription>
                  Create a new device profile with network phase configurations
                </DialogDescription>
              </DialogHeader>
              <form onSubmit={handleCreateProfile}>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label htmlFor="name">Profile Name</Label>
                    <Input
                      id="name"
                      name="name"
                      placeholder="e.g., Production Server Profile"
                      required
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="model">Model</Label>
                    <Input
                      id="model"
                      name="model"
                      placeholder="Optional device model"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="role">Device Role</Label>
                    <Select name="role" defaultValue="server">
                      <SelectTrigger>
                        <SelectValue placeholder="Select device role" />
                      </SelectTrigger>
                      <SelectContent>
                        {ASSIGNABLE_DEVICE_ROLES.map((role) => (
                          <SelectItem key={role} value={role}>
                            {deviceRoleLabel(role)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={createProfileMutation.isLoading}>
                    {createProfileMutation.isLoading && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Create Profile
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {registeredTotal !== undefined && (
        <p data-testid="profile-count" className="text-sm text-muted-foreground">
          Showing {filteredProfiles.length} of {registeredTotal} registered profiles
          {registeredTotal > loadedCount && (
            <> (only the first {loadedCount} are loaded)</>
          )}
        </p>
      )}

      <Card data-testid="profile-lookup">
        <CardHeader>
          <CardTitle>Find a profile</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="profile-lookup-query">Serial or MAC address</Label>
            <Input
              id="profile-lookup-query"
              value={lookupQuery}
              onChange={(e) => {
                setLookupQuery(e.target.value);
                setLookup(null);
              }}
            />
          </div>
          <div className="flex gap-2">
            <Button type="button" variant="outline" disabled={lookupDisabled} onClick={() => findProfile('serial')}>
              Find by serial
            </Button>
            <Button type="button" variant="outline" disabled={lookupDisabled} onClick={() => findProfile('mac')}>
              Find by MAC
            </Button>
          </div>
          {lookup?.kind === 'found' && (
            <p data-testid="profile-lookup-result" className="text-sm">
              <Link href={`/devices/profiles/${lookup.profile.id}`}>{lookup.profile.name}</Link>{' '}
              ({deviceRoleLabel(lookup.profile.role)})
            </p>
          )}
          {lookup?.kind === 'none' && (
            <p data-testid="profile-lookup-result" className="text-sm text-muted-foreground">
              {`No profile matches ${lookup.query}`}
            </p>
          )}
          {lookup?.kind === 'error' && (
            <p data-testid="profile-lookup-error" className="text-sm text-destructive">
              Lookup refused: {lookup.message}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Profiles</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{registeredTotal ?? stats.total}</div>
            <p className="text-xs text-muted-foreground">All device profiles</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Servers</CardTitle>
            <Settings2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.byRole.server || 0}
            </div>
            <p className="text-xs text-muted-foreground">Server profiles</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Workstations</CardTitle>
            <Pencil className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {stats.byRole.workstation || 0}
            </div>
            <p className="text-xs text-muted-foreground">Workstation profiles</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">IoT Devices</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {stats.byRole.iot || 0}
            </div>
            <p className="text-xs text-muted-foreground">IoT profiles</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <Filter className="h-5 w-5 text-muted-foreground" />
        <div className="flex flex-1 items-center gap-4">
          <Input
            placeholder="Search profiles..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.role || 'all'}
            onValueChange={(value) =>
              handleFilterChange('role', value === 'all' ? '' : value)
            }
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="All roles" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All roles</SelectItem>
              {DEVICE_ROLES.map((role) => (
                <SelectItem key={role} value={role}>
                  {deviceRoleLabel(role)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {(filters.role || filters.search) && (
            <Button variant="ghost" onClick={() => setFilters({})}>
              Clear filters
            </Button>
          )}
        </div>
      </div>

      {/* Profiles Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin mx-auto" />
            <p className="mt-2 text-sm text-muted-foreground">Loading profiles...</p>
          </div>
        </div>
      ) : (
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Model</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>
                  <div className="flex items-center gap-1">
                    <Network className="h-4 w-4" />
                    Networks
                  </div>
                </TableHead>
                <TableHead>
                  <div className="flex items-center gap-1">
                    <Shield className="h-4 w-4" />
                    PCR Baseline
                  </div>
                </TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredProfiles.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {filters.search || filters.role
                      ? 'No profiles match your filters'
                      : 'No device profiles found'}
                  </TableCell>
                </TableRow>
              ) : (
                filteredProfiles.map((profile) => (
                  <TableRow key={profile.id}>
                    <TableCell>
                      <div className="font-medium">{profile.name}</div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {profile.model || '-'}
                      </span>
                    </TableCell>
                    <TableCell>{getRoleBadge(profile.role)}</TableCell>
                    <TableCell>
                      <ProfileNetworksCell profile={profile} />
                    </TableCell>
                    <TableCell>
                      <ProfileBaselineCell profile={profile} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatDate(profile.updated_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={deleteProfileMutation.isLoading}
                          >
                            <MoreHorizontal className="h-4 w-4" />
                            <span className="sr-only">Open menu</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => handleViewProfile(profile)}>
                            <Eye className="mr-2 h-4 w-4" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleEditProfile(profile)}>
                            <Pencil className="mr-2 h-4 w-4" />
                            Edit Profile
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDuplicateProfile(profile)}>
                            <Copy className="mr-2 h-4 w-4" />
                            Duplicate
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleDeleteProfile(profile)}
                            className="text-destructive"
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

"use client";

/**
 * Tenant Dashboard Page
 *
 * Displays tenant information, members, and invitations.
 * Uses the trusted-platform-sdk for API interactions.
 */

import * as React from "react";
import { Building2, Mail, Settings, Users, AlertCircle, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/contexts/AuthContext";
import { useTenant, useIAM, useApi, useToast } from "@/hooks";
import type { Tenant, TenantSettings } from "@/types/tenant";

// Extended tenant type for UI with computed settings
interface UITenant extends Tenant {
  plan: 'free' | 'pro' | 'enterprise';
  settings: TenantSettings;
}

// SDK Tenant type
interface SDKTenant {
  id: string;
  name: string;
  displayName?: string;
  state?: string;
  vlanRangeStart?: number;
  vlanRangeEnd?: number;
  computeQuota?: { maxVms?: number; maxVcpus?: number; maxMemoryMb?: number; maxDiskGb?: number; maxContainers?: number };
  networkQuota?: { maxBridges?: number; maxPorts?: number; maxBandwidthMbps?: number };
  storageQuota?: { maxVolumesGb?: number; maxSnapshots?: number };
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  createdAt?: string;
  updatedAt?: string;
}

// Convert backend tenant to UI format
function toUITenant(tenant: SDKTenant): UITenant {
  let plan: 'free' | 'pro' | 'enterprise' = 'free';
  if (tenant.labels?.plan) {
    plan = tenant.labels.plan as 'free' | 'pro' | 'enterprise';
  } else if (tenant.computeQuota && (tenant.computeQuota.maxVms || 0) > 10) {
    plan = 'enterprise';
  } else if (tenant.computeQuota && (tenant.computeQuota.maxVms || 0) > 5) {
    plan = 'pro';
  }

  const settings: TenantSettings = {
    allowedDomains: tenant.labels?.allowed_domains?.split(',').filter(Boolean) || [],
    maxMembers: tenant.computeQuota?.maxVcpus || 10,
    features: tenant.annotations?.features?.split(',').filter(Boolean) || [],
  };

  return {
    id: tenant.id,
    name: tenant.name,
    display_name: tenant.displayName || tenant.name,
    state: (tenant.state as 'created' | 'active' | 'suspended' | 'deleted') || 'active',
    vlan_range: tenant.vlanRangeStart && tenant.vlanRangeEnd ? {
      start: tenant.vlanRangeStart,
      end: tenant.vlanRangeEnd,
    } : undefined,
    compute_quota: tenant.computeQuota ? {
      max_vms: tenant.computeQuota.maxVms || 0,
      max_containers: tenant.computeQuota.maxContainers || 0,
      max_vcpus: tenant.computeQuota.maxVcpus || 0,
      max_memory_mb: tenant.computeQuota.maxMemoryMb || 0,
      max_disk_gb: tenant.computeQuota.maxDiskGb || 0,
    } : undefined,
    network_quota: tenant.networkQuota ? {
      max_bridges: tenant.networkQuota.maxBridges || 0,
      max_ports: tenant.networkQuota.maxPorts || 0,
      max_bandwidth_mbps: tenant.networkQuota.maxBandwidthMbps || 0,
    } : undefined,
    storage_quota: tenant.storageQuota ? {
      max_volumes_gb: tenant.storageQuota.maxVolumesGb || 0,
      max_snapshots: tenant.storageQuota.maxSnapshots || 0,
    } : undefined,
    labels: tenant.labels,
    annotations: tenant.annotations,
    created_at: tenant.createdAt || new Date().toISOString(),
    updated_at: tenant.updatedAt || new Date().toISOString(),
    plan,
    settings,
  };
}

export default function TenantPage() {
  const { tenantId, isLoading: authLoading } = useAuth();
  const { toast } = useToast();
  const tenantService = useTenant();
  const iam = useIAM();

  // Fetch tenant data using SDK
  const {
    data: tenantData,
    isLoading: tenantLoading,
    error: tenantError,
    refetch: refetchTenant,
  } = useApi(
    () => tenantId ? tenantService.getTenant(tenantId) : Promise.resolve({ success: true, data: null }),
    [tenantId],
    {
      onError: (err) => {
        toast({
          title: "Error loading tenant",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Fetch users (members) using SDK
  const {
    data: usersData,
    isLoading: usersLoading,
  } = useApi(
    () => tenantId ? iam.listUsers({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId]
  );

  // Transform data
  const tenant = React.useMemo(() => {
    if (!tenantData?.tenant) return null;
    return toUITenant(tenantData.tenant);
  }, [tenantData]);

  const members = usersData?.users || [];
  const activeMembers = members.length;
  // Note: Invitations endpoint not yet available in SDK, using placeholder
  const pendingInvitations = 0;

  const isLoading = authLoading || tenantLoading || usersLoading;

  const fetchData = () => {
    refetchTenant();
  };

  if (tenantError) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Tenant"
          description="Manage your organization settings"
        />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center text-center space-y-4">
              <AlertCircle className="h-12 w-12 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Error loading tenant</p>
                <p className="text-sm text-muted-foreground mt-1">{tenantError.message}</p>
              </div>
              <Button onClick={fetchData} variant="outline">
                <RefreshCw className="h-4 w-4 mr-2" />
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!tenantId) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Tenant"
          description="Manage your organization settings"
        />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center text-center space-y-4">
              <Building2 className="h-12 w-12 text-muted-foreground" />
              <div>
                <p className="font-medium">No tenant selected</p>
                <p className="text-sm text-muted-foreground mt-1">
                  You are not currently associated with a tenant. Contact your administrator or create a new organization.
                </p>
              </div>
              <Button onClick={() => window.location.href = '/admin/tenant'}>
                Create Organization
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tenant"
        description="Manage your organization settings and members"
      />

      {isLoading || !tenant ? (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <Skeleton className="h-8 w-64" />
              <Skeleton className="h-4 w-48 mt-2" />
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <Skeleton className="h-20" />
                <Skeleton className="h-20" />
                <Skeleton className="h-20" />
              </div>
            </CardContent>
          </Card>
        </div>
      ) : (
        <>
          {/* Tenant Info Card */}
          <Card>
            <CardHeader className="flex flex-row items-start justify-between space-y-0">
              <div className="space-y-1">
                <CardTitle className="flex items-center gap-2">
                  <Building2 className="h-5 w-5" />
                  {tenant.display_name || tenant.name}
                </CardTitle>
                <CardDescription>
                  {tenant.state && (
                    <Badge
                      variant={tenant.state === "active" ? "default" : "secondary"}
                      className="mr-2"
                    >
                      {tenant.state}
                    </Badge>
                  )}
                  Created{" "}
                  {new Date(tenant.created_at).toLocaleDateString("en-US", {
                    month: "long",
                    day: "numeric",
                    year: "numeric",
                  })}
                </CardDescription>
              </div>
              <Badge variant="outline">{tenant.plan}</Badge>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Total Members</p>
                  <p className="text-2xl font-bold">{members.length}</p>
                  <p className="text-xs text-muted-foreground">
                    Max: {tenant.settings.maxMembers}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Active</p>
                  <p className="text-2xl font-bold">{activeMembers}</p>
                  <p className="text-xs text-green-500">
                    {members.length > 0
                      ? Math.round((activeMembers / members.length) * 100)
                      : 0}
                    % active
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Pending Invitations</p>
                  <p className="text-2xl font-bold">{pendingInvitations}</p>
                  <p className="text-xs text-muted-foreground">Awaiting acceptance</p>
                </div>
              </div>

              {tenant.settings.features.length > 0 && (
                <>
                  <Separator className="my-4" />
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Enabled Features</p>
                    <div className="flex flex-wrap gap-2">
                      {tenant.settings.features.map((feature) => (
                        <Badge key={feature} variant="outline">
                          {feature}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {tenant.settings.allowedDomains && tenant.settings.allowedDomains.length > 0 && (
                <>
                  <Separator className="my-4" />
                  <div className="space-y-2">
                    <p className="text-sm font-medium">Allowed Domains</p>
                    <div className="flex flex-wrap gap-2">
                      {tenant.settings.allowedDomains.map((domain) => (
                        <Badge key={domain} variant="secondary">
                          {domain}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Members
                </CardTitle>
                <CardDescription>
                  Manage team members and their roles
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-2xl font-bold">{members.length}</p>
                      <p className="text-sm text-muted-foreground">
                        Total members
                      </p>
                    </div>
                    <Button asChild>
                      <a href="/tenant/members">View All Members</a>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Mail className="h-5 w-5" />
                  Invitations
                </CardTitle>
                <CardDescription>Pending invitations to join</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-2xl font-bold">{pendingInvitations}</p>
                      <p className="text-sm text-muted-foreground">
                        Awaiting acceptance
                      </p>
                    </div>
                    <Button asChild variant="outline">
                      <a href="/tenant/invitations">Manage Invitations</a>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Quick Settings
              </CardTitle>
              <CardDescription>Common configuration options</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                <Button variant="outline" className="h-auto justify-start p-4">
                  <div className="text-left">
                    <p className="font-medium">Domain Settings</p>
                    <p className="text-sm text-muted-foreground">
                      Configure allowed email domains
                    </p>
                  </div>
                </Button>
                <Button variant="outline" className="h-auto justify-start p-4" asChild>
                  <a href="/tenant/quotas">
                    <div className="text-left">
                      <p className="font-medium">Resource Quotas</p>
                      <p className="text-sm text-muted-foreground">
                        View compute, network, storage limits
                      </p>
                    </div>
                  </a>
                </Button>
                <Button variant="outline" className="h-auto justify-start p-4">
                  <div className="text-left">
                    <p className="font-medium">Feature Access</p>
                    <p className="text-sm text-muted-foreground">
                      Enable or disable features
                    </p>
                  </div>
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

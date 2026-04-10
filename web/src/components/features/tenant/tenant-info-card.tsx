"use client";

import * as React from "react";
import { Building2, Crown, Edit } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import type { Tenant, TenantSettings } from "@/types/tenant";

// Extended tenant type for UI display
interface UITenant extends Tenant {
  plan?: 'free' | 'pro' | 'enterprise';
  settings?: TenantSettings;
}

interface TenantInfoCardProps {
  tenant: UITenant;
  memberCount: number;
  activeCount: number;
  pendingInvitations: number;
  onEdit?: () => void;
}

type PlanType = 'free' | 'pro' | 'enterprise';

const planColors: Record<PlanType, "secondary" | "default"> = {
  free: "secondary",
  pro: "default",
  enterprise: "default",
};

const planIcons: Record<PlanType, typeof Crown | null> = {
  free: null,
  pro: Crown,
  enterprise: Crown,
};

export function TenantInfoCard({
  tenant,
  memberCount,
  activeCount,
  pendingInvitations,
  onEdit,
}: TenantInfoCardProps) {
  const plan = tenant.plan || 'free';
  const PlanIcon = planIcons[plan];

  // Use display_name or name from new API
  const displayName = tenant.display_name || tenant.name;

  // Format created date
  const createdAt = tenant.created_at
    ? new Date(tenant.created_at).toLocaleDateString("en-US", {
        month: "long",
        day: "numeric",
        year: "numeric",
      })
    : "Unknown";

  // Get settings with defaults
  const settings = tenant.settings || { maxMembers: 10, features: [], allowedDomains: [] };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            {displayName}
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
            Created {createdAt}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={planColors[plan]}>
            {PlanIcon && <PlanIcon className="h-3 w-3 mr-1" />}
            {plan.charAt(0).toUpperCase() + plan.slice(1)}
          </Badge>
          {onEdit && (
            <Button variant="outline" size="sm" onClick={onEdit}>
              <Edit className="h-4 w-4 mr-2" />
              Edit
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-1">
            <p className="text-sm text-muted-foreground">Total Members</p>
            <p className="text-2xl font-bold">{memberCount}</p>
            <p className="text-xs text-muted-foreground">
              Max: {settings.maxMembers}
            </p>
          </div>
          <div className="space-y-1">
            <p className="text-sm text-muted-foreground">Active</p>
            <p className="text-2xl font-bold">{activeCount}</p>
            <p className="text-xs text-green-500">
              {memberCount > 0
                ? Math.round((activeCount / memberCount) * 100)
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

        {settings.features && settings.features.length > 0 && (
          <>
            <Separator className="my-4" />
            <div className="space-y-2">
              <p className="text-sm font-medium">Enabled Features</p>
              <div className="flex flex-wrap gap-2">
                {settings.features.map((feature) => (
                  <Badge key={feature} variant="outline">
                    {feature}
                  </Badge>
                ))}
              </div>
            </div>
          </>
        )}

        {settings.allowedDomains && settings.allowedDomains.length > 0 && (
          <>
            <Separator className="my-4" />
            <div className="space-y-2">
              <p className="text-sm font-medium">Allowed Domains</p>
              <div className="flex flex-wrap gap-2">
                {settings.allowedDomains.map((domain) => (
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
  );
}

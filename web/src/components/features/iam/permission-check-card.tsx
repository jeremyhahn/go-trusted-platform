"use client";

/**
 * Checks one subject/action/resource triple against the tenant's policies
 * through POST /tenants/{tenant}/permissions/check (#1744).
 * Check is gated on the server's capability for that op (#2033, #2053).
 */

import React, { useState } from "react";
import { CheckCircle2, Loader2, ShieldQuestion, XCircle } from "lucide-react";
import type { CheckIAMPermissionResponse } from "trusted-platform-sdk";
import { useIAM, useMutation } from "@/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Gated } from "@/components/features/capabilities/gated";

export interface PermissionCheckCardProps {
  tenantId: string;
  defaultSubjectId?: string;
}

/** Parses a comma-separated list, dropping blanks. */
function parseList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function PermissionCheckCard({ tenantId, defaultSubjectId = "" }: PermissionCheckCardProps) {
  const iam = useIAM();
  const [subjectId, setSubjectId] = useState(defaultSubjectId);
  const [action, setAction] = useState("");
  const [resource, setResource] = useState("");
  const [roles, setRoles] = useState("");
  const [groups, setGroups] = useState("");

  // Each verdict carries the tenant and inputs it was checked for, so a
  // verdict is shown only beneath those same inputs. Roles and groups feed
  // the PEP subject, so a role-granted permission is not shown Denied.
  type Checked = {
    tenantId: string;
    subjectId: string;
    action: string;
    resource: string;
    roles: string[];
    groups: string[];
  };
  const [checked, setChecked] = useState<Checked | null>(null);
  const check = useMutation((vars: Checked) =>
    iam.checkPermission({
      tenantId: vars.tenantId,
      subjectId: vars.subjectId,
      action: vars.action,
      resource: vars.resource,
      ...(vars.roles.length ? { roles: vars.roles } : {}),
      ...(vars.groups.length ? { groups: vars.groups } : {}),
    })
  );

  const roleList = parseList(roles);
  const groupList = parseList(groups);
  const data = check.data as CheckIAMPermissionResponse | undefined;
  const result =
    data &&
    checked &&
    !check.isLoading &&
    checked.tenantId === tenantId &&
    checked.subjectId === subjectId.trim() &&
    checked.action === action.trim() &&
    checked.resource === resource.trim() &&
    checked.roles.join(",") === roleList.join(",") &&
    checked.groups.join(",") === groupList.join(",")
      ? data
      : undefined;
  const ready = subjectId.trim() && action.trim() && resource.trim();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldQuestion className="h-5 w-5 text-muted-foreground" /> Check permission
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="grid gap-4 md:grid-cols-3 items-end"
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();
            if (ready) {
              const vars = {
                tenantId,
                subjectId: subjectId.trim(),
                action: action.trim(),
                resource: resource.trim(),
                roles: roleList,
                groups: groupList,
              };
              setChecked(vars);
              check.mutate(vars);
            }
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="perm-check-subject">Subject ID</Label>
            <Input id="perm-check-subject" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="perm-check-action">Action</Label>
            <Input id="perm-check-action" value={action} onChange={(e) => setAction(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="perm-check-resource">Resource</Label>
            <Input id="perm-check-resource" value={resource} onChange={(e) => setResource(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="perm-check-roles">Roles</Label>
            <Input
              id="perm-check-roles"
              placeholder="comma-separated, optional"
              value={roles}
              onChange={(e) => setRoles(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="perm-check-groups">Groups</Label>
            <Input
              id="perm-check-groups"
              placeholder="comma-separated, optional"
              value={groups}
              onChange={(e) => setGroups(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/iam/tenants/{tenant}/permissions/check">
            <Button type="submit" disabled={check.isLoading || !ready}>
              {check.isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Check
            </Button>
          </Gated>
        </form>
        {check.error && (
          <p role="status" className="text-sm text-destructive">
            Check failed: {check.error.message}
          </p>
        )}
        {result && !check.error && (
          <div role="status" className="flex items-center gap-2 text-sm">
            {result.allowed ? (
              <>
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <span className="font-medium">Allowed</span>
              </>
            ) : (
              <>
                <XCircle className="h-4 w-4 text-destructive" />
                <span className="font-medium">Denied</span>
              </>
            )}
            {result.matchedPolicy && <span>by policy {result.matchedPolicy}</span>}
            {result.reason && <span className="text-muted-foreground">({result.reason})</span>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

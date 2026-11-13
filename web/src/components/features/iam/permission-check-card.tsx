"use client";

/**
 * Checks one subject/action/resource triple against the tenant's policies
 * through POST /tenants/{tenant}/permissions/check (#1744).
 */

import React, { useState } from "react";
import { CheckCircle2, Loader2, ShieldQuestion, XCircle } from "lucide-react";
import type { CheckIAMPermissionResponse } from "trusted-platform-sdk";
import { useIAM, useMutation } from "@/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export interface PermissionCheckCardProps {
  tenantId: string;
  defaultSubjectId?: string;
}

export function PermissionCheckCard({ tenantId, defaultSubjectId = "" }: PermissionCheckCardProps) {
  const iam = useIAM();
  const [subjectId, setSubjectId] = useState(defaultSubjectId);
  const [action, setAction] = useState("");
  const [resource, setResource] = useState("");

  const check = useMutation((vars: { subjectId: string; action: string; resource: string }) =>
    iam.checkPermission({ tenantId, ...vars }),
  );

  const result = check.data as CheckIAMPermissionResponse | undefined;
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
          className="grid gap-4 md:grid-cols-4 items-end"
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();
            if (ready) {
              check.mutate({
                subjectId: subjectId.trim(),
                action: action.trim(),
                resource: resource.trim(),
              });
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
          <Button type="submit" disabled={check.isLoading || !ready}>
            {check.isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Check
          </Button>
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

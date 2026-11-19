"use client";

/**
 * Policy test page: validate a policy document (POST /policies/validate)
 * and evaluate a request against the tenant's policies (POST /policies/test).
 */

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, CheckCircle2, Loader2, XCircle } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { usePolicyTools, splitList } from "@/hooks";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";

// Result shapes as the REST API sends them: camelCase or snake_case keys (#445).
interface ValidateWire {
  valid?: boolean;
  errors?: string[];
}

interface TestWire {
  allowed?: boolean;
  matchedPolicy?: string;
  matched_policy?: string;
  matchedRule?: string;
  matched_rule?: string;
}

const SAMPLE_POLICY = [
  "apiVersion: v1",
  "kind: Policy",
  "metadata:",
  "  name: allow-read",
  "spec:",
  "  rules:",
  "    - name: rule-1",
  "      effect: allow",
  "      actions: [read]",
  '      resources: ["*"]',
].join("\n");

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

export default function PolicyTestPage() {
  const router = useRouter();
  const { tenantId } = useAuth();
  const { validate, test } = usePolicyTools();

  const [specYaml, setSpecYaml] = useState(SAMPLE_POLICY);
  const [subjectId, setSubjectId] = useState("");
  const [roles, setRoles] = useState("");
  const [groups, setGroups] = useState("");
  const [action, setAction] = useState("read");
  const [resource, setResource] = useState("");

  const validation = validate.data as ValidateWire | undefined;
  const evaluation = test.data as TestWire | undefined;
  const matchedPolicy = evaluation?.matchedPolicy ?? evaluation?.matched_policy;
  const matchedRule = evaluation?.matchedRule ?? evaluation?.matched_rule;

  return (
    <div className="container mx-auto py-6 space-y-6 max-w-3xl">
      <Button variant="ghost" size="sm" onClick={() => router.push("/iam/policies")}>
        <ArrowLeft className="h-4 w-4 mr-2" /> Back to Policies
      </Button>
      <h1 className="text-2xl font-bold">Policy Test</h1>

      <Card>
        <CardHeader>
          <CardTitle>Validate Policy</CardTitle>
          <CardDescription>Check a policy document before you save it.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="spec-yaml">Policy YAML</Label>
            <Textarea
              id="spec-yaml"
              value={specYaml}
              onChange={(e) => setSpecYaml(e.target.value)}
              rows={12}
              className="font-mono text-xs"
            />
          </div>
          <div className="flex justify-end">
            <Button
              onClick={() => {
                if (tenantId) validate.mutate({ tenantId, specYaml });
              }}
              disabled={!tenantId || !specYaml || validate.isLoading}
            >
              {validate.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Validate
            </Button>
          </div>
          {validate.isError && (
            <p className="text-sm text-destructive" role="alert">
              Validation failed: {errorMessage(validate.error)}
            </p>
          )}
          {validation && (
            <div className="space-y-2" data-testid="validate-result">
              {validation.valid ? (
                <p className="flex items-center gap-2 text-sm text-green-600">
                  <CheckCircle2 className="h-4 w-4" /> Policy is valid
                </p>
              ) : (
                <p className="flex items-center gap-2 text-sm text-destructive">
                  <XCircle className="h-4 w-4" /> Policy is invalid
                </p>
              )}
              {(validation.errors ?? []).length > 0 && (
                <ul className="list-disc pl-6 text-sm">
                  {(validation.errors ?? []).map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Test Access</CardTitle>
          <CardDescription>
            Evaluate a request against this tenant&apos;s policies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="subject-id">Subject ID *</Label>
              <Input id="subject-id" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="action">Action *</Label>
              <Input id="action" value={action} onChange={(e) => setAction(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="resource">Resource *</Label>
              <Input id="resource" value={resource} onChange={(e) => setResource(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="roles">Roles (comma-separated)</Label>
              <Input id="roles" value={roles} onChange={(e) => setRoles(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="groups">Groups (comma-separated)</Label>
              <Input id="groups" value={groups} onChange={(e) => setGroups(e.target.value)} />
            </div>
          </div>
          <div className="flex justify-end">
            <Button
              onClick={() => {
                if (!tenantId) return;
                test.mutate({
                  tenantId,
                  subjectId,
                  action,
                  resource,
                  roles: splitList(roles),
                  groups: splitList(groups),
                });
              }}
              disabled={!tenantId || !subjectId || !action || !resource || test.isLoading}
            >
              {test.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Run Test
            </Button>
          </div>
          {test.isError && (
            <p className="text-sm text-destructive" role="alert">
              Test failed: {errorMessage(test.error)}
            </p>
          )}
          {evaluation && (
            <div className="space-y-1 text-sm" data-testid="test-result">
              <Badge variant={evaluation.allowed ? "default" : "destructive"}>
                {evaluation.allowed ? "Allowed" : "Denied"}
              </Badge>
              {matchedPolicy && <p>Matched policy: {matchedPolicy}</p>}
              {matchedRule && <p>Matched rule: {matchedRule}</p>}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

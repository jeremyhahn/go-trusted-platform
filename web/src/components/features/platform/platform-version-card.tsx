"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePlatformVersion } from "@/hooks/use-platform-version";

/**
 * PlatformVersionCard shows the daemon build the control plane reports on
 * GET /platform/version. It is read-only: no controls, no toast.
 */
export function PlatformVersionCard() {
  const { version, error, isLoading } = usePlatformVersion();
  const shown = (v: string) => (v === "" ? "—" : v);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Platform version</CardTitle>
      </CardHeader>
      <CardContent>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            Version unavailable: {error}
          </p>
        ) : version ? (
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Version</dt>
            <dd>{shown(version.version)}</dd>
            <dt className="text-muted-foreground">Git commit</dt>
            <dd className="font-mono">{shown(version.gitCommit)}</dd>
            <dt className="text-muted-foreground">Build time</dt>
            <dd>{shown(version.buildTime)}</dd>
            <dt className="text-muted-foreground">Go version</dt>
            <dd>{shown(version.goVersion)}</dd>
          </dl>
        ) : isLoading ? (
          <p className="text-sm text-muted-foreground">Loading version…</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

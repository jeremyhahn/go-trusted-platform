"use client";

/**
 * Cluster page: a read-only view of cluster membership and node health.
 *
 * Reads GET /v1/cluster/status and GET /v1/cluster/nodes through the
 * useCluster hook (SDK ApiClient). A 503 means the daemon has no cluster
 * service configured; the page says so plainly and shows no node table.
 */

import * as React from "react";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi } from "@/hooks";
import {
  clusterStateLabel,
  nodeRoleLabel,
  nodeStateLabel,
  useCluster,
} from "@/hooks/use-cluster";
import { ClusterMembershipCard } from "./cluster-membership-card";

export default function ClusterPage() {
  const cluster = useCluster();
  const status = useApi(() => cluster.getStatus(), [cluster]);
  const nodes = useApi(() => cluster.listNodes(), [cluster]);

  const notConfigured = status.error?.status === 503;
  const info = status.data?.cluster;

  return (
    <div className="space-y-6">
      <PageHeader title="Cluster" description="Cluster membership and node health">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void status.refetch();
            void nodes.refetch();
          }}
        >
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </PageHeader>

      {notConfigured ? (
        <Card data-testid="cluster-not-configured">
          <CardHeader>
            <CardTitle>Cluster not configured</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{status.error?.message}</p>
          </CardContent>
        </Card>
      ) : (
        <>
          {status.error ? (
            <p role="alert" className="text-sm text-destructive">
              {status.error.message}
            </p>
          ) : (
            <Card data-testid="cluster-status">
              <CardHeader>
                <CardTitle>Status</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-5">
                  <div>
                    <dt className="text-muted-foreground">Name</dt>
                    <dd>{info?.name}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">State</dt>
                    <dd>{clusterStateLabel(info?.state)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Leader</dt>
                    <dd>{info?.leader_id}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Healthy nodes</dt>
                    <dd>{`${info?.healthy_nodes ?? 0} / ${info?.total_nodes ?? 0}`}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Term</dt>
                    <dd>{String(info?.term ?? "-")}</dd>
                  </div>
                </dl>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Nodes</CardTitle>
            </CardHeader>
            <CardContent>
              {nodes.error ? (
                <p role="alert" className="text-sm text-destructive">
                  {nodes.error.message}
                </p>
              ) : (
                <Table data-testid="cluster-nodes">
                  <TableHeader>
                    <TableRow>
                      <TableHead>ID</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Address</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>State</TableHead>
                      <TableHead>Version</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(nodes.data?.nodes ?? []).map((n) => (
                      <TableRow key={n.id}>
                        <TableCell>{n.id}</TableCell>
                        <TableCell>{n.name}</TableCell>
                        <TableCell>{n.address ? `${n.address}:${n.port}` : "-"}</TableCell>
                        <TableCell>{nodeRoleLabel(n.role)}</TableCell>
                        <TableCell>{nodeStateLabel(n.state)}</TableCell>
                        <TableCell>{n.version}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <ClusterMembershipCard localNodeId={status.data?.local_node?.id} onChanged={() => { void status.refetch(); void nodes.refetch(); }} />
        </>
      )}
    </div>
  );
}

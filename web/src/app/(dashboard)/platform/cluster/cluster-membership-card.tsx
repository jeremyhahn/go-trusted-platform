"use client";

/**
 * Membership card on the cluster page: bootstrap a cluster, join one through
 * its seeds, or leave it (behind a confirm). Every write goes through the
 * useCluster hook (SDK ApiClient, POST /v1/cluster/{bootstrap,join,leave}).
 * The daemon takes the node's bind and announced network addresses from its
 * cluster configuration (pkg/api/daemon/cluster_grpc_backend.go Bootstrap and
 * Join), and its Leave has no Force option, so the card offers no such fields.
 */

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks";
import { useCluster } from "@/hooks/use-cluster";

/** "192.0.2.11:7946, 192.0.2.12:7946\n" -> ["192.0.2.11:7946", "192.0.2.12:7946"]: split on commas and newlines, trimmed, blanks dropped. */
export function parseSeedAddresses(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((p) => p.trim())
    .filter((p) => p !== "");
}

interface WriteResult {
  success: boolean;
  data?: { status?: { success?: boolean; message?: string } } | null;
  error?: { message?: string } | null;
}

export function ClusterMembershipCard(props: { localNodeId?: string; onChanged: () => void }) {
  const { localNodeId, onChanged } = props;
  const cluster = useCluster();
  const { toast } = useToast();

  const [clusterName, setClusterName] = React.useState("");
  const [nodeName, setNodeName] = React.useState("");

  const [joinName, setJoinName] = React.useState("");
  const [seeds, setSeeds] = React.useState("");

  const [nodeId, setNodeId] = React.useState(localNodeId ?? "");
  const [nodeIdTouched, setNodeIdTouched] = React.useState(false);
  const [confirmOpen, setConfirmOpen] = React.useState(false);

  const [pending, setPending] = React.useState<"bootstrap" | "join" | "leave" | null>(null);

  React.useEffect(() => {
    if (!nodeIdTouched) setNodeId(localNodeId ?? "");
  }, [localNodeId, nodeIdTouched]);

  const seedList = parseSeedAddresses(seeds);

  const settle = (res: WriteResult, title: string, fallback: string) => {
    if (res.success && res.data?.status?.success !== false) {
      toast({ title, description: res.data?.status?.message || fallback });
      setConfirmOpen(false);
      onChanged();
      return;
    }
    toast({
      title: "Cluster request failed",
      description: res.error?.message ?? res.data?.status?.message,
      variant: "destructive",
    });
  };

  const run = async (kind: "bootstrap" | "join" | "leave", write: () => Promise<WriteResult>, title: string, fallback: string) => {
    setPending(kind);
    try {
      settle(await write(), title, fallback);
    } finally {
      setPending(null);
    }
  };

  const onBootstrap = () => {
    const name = clusterName.trim();
    const node = nodeName.trim();
    void run(
      "bootstrap",
      () => cluster.bootstrap({ cluster_name: name, node_name: node }),
      "Cluster bootstrapped",
      name,
    );
  };

  const onJoin = () => {
    const node = joinName.trim();
    void run(
      "join",
      () => cluster.join({ node_name: node, seed_addresses: seedList }),
      "Node joined",
      node,
    );
  };

  const onLeave = () => {
    const id = nodeId.trim();
    void run("leave", () => cluster.leave({ node_id: id }), "Node left", id);
  };

  const bootstrapDisabled = pending === "bootstrap" || clusterName.trim() === "" || nodeName.trim() === "";
  const joinDisabled = pending === "join" || joinName.trim() === "" || seedList.length === 0;
  const leaveDisabled = pending === "leave" || nodeId.trim() === "";

  return (
    <Card data-testid="cluster-membership">
      <CardHeader>
        <CardTitle>Membership</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <section data-testid="cluster-bootstrap" className="space-y-2">
          <h3 className="text-sm font-medium">Bootstrap</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <Input aria-label="Cluster name" value={clusterName} onChange={(e) => setClusterName(e.target.value)} />
            <Input aria-label="Node name" value={nodeName} onChange={(e) => setNodeName(e.target.value)} />
          </div>
          <Button size="sm" disabled={bootstrapDisabled} onClick={onBootstrap}>
            Bootstrap
          </Button>
        </section>

        <section data-testid="cluster-join" className="space-y-2">
          <h3 className="text-sm font-medium">Join</h3>
          <Input aria-label="Join node name" value={joinName} onChange={(e) => setJoinName(e.target.value)} />
          <Textarea
            aria-label="Seed addresses"
            placeholder="192.0.2.11:7946"
            value={seeds}
            onChange={(e) => setSeeds(e.target.value)}
          />
          <Button size="sm" disabled={joinDisabled} onClick={onJoin}>
            Join
          </Button>
        </section>

        <section data-testid="cluster-leave" className="space-y-2">
          <h3 className="text-sm font-medium">Leave</h3>
          <div className="flex flex-wrap items-center gap-4">
            <Input
              aria-label="Node ID"
              className="max-w-xs"
              value={nodeId}
              onChange={(e) => {
                setNodeIdTouched(true);
                setNodeId(e.target.value);
              }}
            />
          </div>
          <Button size="sm" variant="destructive" disabled={leaveDisabled} onClick={() => setConfirmOpen(true)}>
            Leave
          </Button>
        </section>

        <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Leave cluster</DialogTitle>
              <DialogDescription>
                {`Remove node ${nodeId.trim()} from the cluster? It stops taking part in elections and replication.`}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmOpen(false)}>
                Cancel
              </Button>
              <Button variant="destructive" disabled={pending === "leave"} onClick={onLeave}>
                Leave cluster
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

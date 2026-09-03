"use client";

import { ServerOff } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface ServiceUnavailableStateProps {
  /** Human-readable service name, e.g. "Compute". */
  service: string;
  /** Explains why the service is absent on this node and where it runs. */
  description: string;
}

/**
 * Informational (non-error) state for a page whose backing service is
 * not configured on this node — the API's structured 503 from the
 * service registry. Distinct from an error card: the system is healthy,
 * the service just lives elsewhere in the topology.
 */
export function ServiceUnavailableState({
  service,
  description,
}: ServiceUnavailableStateProps) {
  return (
    <Card>
      <CardHeader className="flex flex-col items-center text-center py-10">
        <ServerOff className="h-10 w-10 text-muted-foreground mb-4" aria-hidden="true" />
        <CardTitle>{service} is not available on this node</CardTitle>
        <CardDescription className="max-w-xl mt-2">{description}</CardDescription>
      </CardHeader>
      <CardContent />
    </Card>
  );
}

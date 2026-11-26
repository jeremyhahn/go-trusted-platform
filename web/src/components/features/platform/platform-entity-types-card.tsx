"use client";

import * as React from "react";
import { usePlatform } from "trusted-platform-sdk";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** The ListEntityTypes answer, as the SDK's listEntityTypes types it. */
type ListEntityTypesResponse = NonNullable<
  Awaited<ReturnType<ReturnType<typeof usePlatform>["listEntityTypes"]>>["data"]
>;

/**
 * PlatformEntityTypesCard lists the entity types the daemon's registry
 * reports on GET /platform/entity-types (ListEntityTypes), each with its
 * entity count, and the total. It is read-only: no controls, no toast.
 */
export function PlatformEntityTypesCard() {
  const platform = usePlatform();
  const [listing, setListing] = React.useState<ListEntityTypesResponse | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);

  React.useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const res = await platform.listEntityTypes();
        if (!live) return;
        if (res.error) {
          setListing(null);
          setError(
            res.error.status !== undefined
              ? `HTTP ${res.error.status}: ${res.error.message}`
              : res.error.message
          );
          return;
        }
        setListing(res.data ?? { entityTypes: [], totalEntities: 0, activeTypes: 0 });
        setError(null);
      } catch (err) {
        if (live) {
          setListing(null);
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (live) setIsLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [platform]);

  const types = listing?.entityTypes ?? [];

  return (
    <Card data-testid="platform-entity-types">
      <CardHeader>
        <CardTitle>Entity types</CardTitle>
      </CardHeader>
      <CardContent>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            Entity types unavailable: {error}
          </p>
        ) : listing ? (
          <div className="space-y-2 text-sm">
            {types.length === 0 ? (
              <p className="text-muted-foreground">No entity types registered.</p>
            ) : (
              <ul className="divide-y">
                {types.map((t) => (
                  <li
                    key={t.name}
                    data-testid={`entity-type-${t.name}`}
                    className="flex items-center justify-between py-1"
                  >
                    <span className="font-mono">{t.name}</span>
                    <span className="flex gap-3">
                      <span className="text-muted-foreground">{t.status}</span>
                      <span>{t.entityCount}</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p data-testid="entity-types-total" className="text-muted-foreground">
              Total entities: {listing.totalEntities}
            </p>
          </div>
        ) : isLoading ? (
          <p className="text-sm text-muted-foreground">Loading entity types…</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

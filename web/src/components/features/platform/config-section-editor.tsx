"use client";

import * as React from "react";
import { usePlatform } from "trusted-platform-sdk";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Gated } from "@/components/features/capabilities/gated";

export interface ConfigSectionEditorProps {
  /** Called once the server has applied the section. */
  onApplied?: () => void;
}

/**
 * ConfigSectionEditor applies one key of one configuration section through
 * UpdateConfig (PUT /api/v1/platform/config/sections/{section}). Apply is
 * capability-gated: the server decides whether it is enabled (#2047).
 */
export function ConfigSectionEditor({ onApplied }: ConfigSectionEditorProps) {
  const platform = usePlatform();
  const [section, setSection] = React.useState("");
  const [key, setKey] = React.useState("");
  const [value, setValue] = React.useState("");
  const [persist, setPersist] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const apply = async () => {
    if (!section.trim() || !key.trim()) {
      setError("Section and Key are required");
      return;
    }
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const res = await platform.updateConfigSection(section.trim(), {
        values: { [key.trim()]: value },
        persist,
      });
      if (res.error) {
        setError(
          res.error.status !== undefined
            ? `HTTP ${res.error.status}: ${res.error.message}`
            : res.error.message
        );
        return;
      }
      setMessage(res.data?.message ?? "Applied");
      onApplied?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const inputClass =
    "w-full rounded-md border border-input bg-background px-3 py-2 text-sm";

  return (
    <Card data-testid="config-section-editor">
      <CardHeader>
        <CardTitle>Update a section</CardTitle>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-3 md:grid-cols-3"
          onSubmit={(e) => {
            e.preventDefault();
            void apply();
          }}
        >
          <label className="space-y-1 text-sm">
            <span>Section</span>
            <input
              aria-label="Section"
              className={inputClass}
              value={section}
              onChange={(e) => setSection(e.target.value)}
            />
          </label>
          <label className="space-y-1 text-sm">
            <span>Key</span>
            <input
              aria-label="Key"
              className={inputClass}
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
          </label>
          <label className="space-y-1 text-sm">
            <span>Value</span>
            <input
              aria-label="Value"
              className={inputClass}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              aria-label="Persist"
              checked={persist}
              onChange={(e) => setPersist(e.target.checked)}
            />
            <span>Persist</span>
          </label>
          <div className="md:col-span-2 flex items-center gap-3">
            <Gated op="PUT /api/v1/platform/config/sections/{section}">
              <Button type="submit" disabled={busy}>
                Apply
              </Button>
            </Gated>
            {message ? (
              <span className="text-sm text-muted-foreground">{message}</span>
            ) : null}
            {error ? (
              <span role="alert" className="text-sm text-destructive">
                {error}
              </span>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

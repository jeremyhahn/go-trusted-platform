import * as React from 'react';
import { usePlatform } from 'trusted-platform-sdk';

/** PlatformVersion is the daemon build the control plane reports. */
export interface PlatformVersion {
  version: string;
  buildTime: string;
  gitCommit: string;
  goVersion: string;
}

// The flat snake_case body of GET /platform/version
// (pkg/webservice/v1/rest/platform/types.go VersionResponse), which differs
// from the SDK's declared GetVersionResponse.
interface VersionWire {
  version?: string;
  build_time?: string;
  git_commit?: string;
  go_version?: string;
}

export interface UsePlatformVersionResult {
  version: PlatformVersion | null;
  error: string | null;
  isLoading: boolean;
  refetch: () => Promise<void>;
}

/**
 * usePlatformVersion reads GET /platform/version through the SDK
 * PlatformService. A refusal or a thrown error becomes `error`, never an
 * unhandled rejection.
 */
export function usePlatformVersion(): UsePlatformVersionResult {
  const platform = usePlatform();
  const [version, setVersion] = React.useState<PlatformVersion | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);

  const read = React.useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await platform.getVersion();
      if (res.error) {
        setVersion(null);
        setError(
          res.error.status !== undefined
            ? `HTTP ${res.error.status}: ${res.error.message}`
            : res.error.message
        );
        return;
      }
      const w = (res.data ?? {}) as unknown as VersionWire;
      setVersion({
        version: w.version ?? '',
        buildTime: w.build_time ?? '',
        gitCommit: w.git_commit ?? '',
        goVersion: w.go_version ?? '',
      });
      setError(null);
    } catch (err) {
      setVersion(null);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [platform]);

  React.useEffect(() => {
    let live = true;
    void (async () => {
      if (live) await read();
    })();
    return () => {
      live = false;
    };
  }, [read]);

  return { version, error, isLoading, refetch: read };
}

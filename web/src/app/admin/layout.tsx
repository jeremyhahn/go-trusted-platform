"use client";

import { useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import { getUserFromToken } from "@/utils/jwt";
import { useHydrated, useSessionToken } from "@/hooks/use-session-token";
import styles from "./AdminLayout.module.css";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const hydrated = useHydrated();
  const token = useSessionToken();
  // Derived from the cookie, not copied into state: re-read when the token
  // changes. `token` is the dependency; getUserFromToken reads the same cookie.
  const user = useMemo(() => (token ? getUserFromToken() : null), [token]);
  // For now, the tenant ID stands in for a name; the backend can provide one later.
  const tenantName = user?.tenantId ?? null;

  useEffect(() => {
    if (hydrated && !user) {
      router.push("/auth/webauthn");
    }
  }, [hydrated, user, router]);

  if (!hydrated || !user) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Verifying authentication...</div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <div className={styles.headerContent}>
          <h1 className={styles.logo}>Trusted Platform</h1>
          {tenantName && (
            <div className={styles.tenantInfo}>
              <span className={styles.tenantLabel}>Workspace:</span>
              <span className={styles.tenantName}>{tenantName}</span>
            </div>
          )}
        </div>
      </header>
      <main className={styles.main}>{children}</main>
    </div>
  );
}

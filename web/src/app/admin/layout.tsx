"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getCookie } from "@/utils/cookie";
import { getUserFromToken } from "@/utils/jwt";
import styles from "./AdminLayout.module.css";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [tenantName, setTenantName] = useState<string | null>(null);

  useEffect(() => {
    const jwt = getCookie("jwt");
    if (!jwt) {
      router.push("/auth/webauthn");
      return;
    }

    const user = getUserFromToken();
    if (!user) {
      router.push("/auth/webauthn");
      return;
    }

    setIsAuthenticated(true);
    // For now, just use tenant ID as name
    // Backend can provide tenant name via API later
    setTenantName(user.tenantId);
  }, [router]);

  if (!isAuthenticated) {
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

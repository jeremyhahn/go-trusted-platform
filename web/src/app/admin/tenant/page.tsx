"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getUserFromToken } from "@/utils/jwt";
import { useTenant } from "@/hooks";
import styles from "./TenantPage.module.css";
import { useLogout } from "@/hooks/use-logout";

interface TenantInfo {
  id: string;
  name?: string;
  state?: string;
}

// #2067: reads the tenant through TenantService.getTenant (GET /api/v1/tenants/{id}); /api/v1/tenant is not served.
export default function TenantPage() {
  const router = useRouter();
  const tenantService = useTenant();
  const [tenantInfo, setTenantInfo] = useState<TenantInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isTenantOwner, setIsTenantOwner] = useState(false);

  useEffect(() => {
    const user = getUserFromToken();
    if (!user) {
      router.push("/auth/webauthn");
      return;
    }

    setIsTenantOwner(user.isTenantOwner);
    if (user.tenantId) {
      fetchTenantInfo(user.tenantId);
    } else {
      // No tenant - show empty state
      setTenantInfo(null);
      setLoading(false);
    }
  }, [router]);

  const fetchTenantInfo = async (tenantId: string) => {
    try {
      const res = await tenantService.getTenant(tenantId);
      if (!res.success || !res.data?.tenant) {
        throw new Error(res.error?.message ?? "Failed to fetch tenant information");
      }

      const t = res.data.tenant;
      setTenantInfo({
        id: tenantId,
        name: t.displayName || t.name,
        state: t.state,
      });
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Failed to fetch tenant info"
      );
      // If API fails, at least show tenant ID
      const user = getUserFromToken();
      if (user && user.tenantId) {
        setTenantInfo({
          id: user.tenantId,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = useLogout();

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading tenant information...</div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Tenant Dashboard</h1>
        <button onClick={handleLogout} className={styles.logoutButton}>
          Logout
        </button>
      </div>

      {error && (
        <div className={styles.errorNotification}>
          {error}
        </div>
      )}

      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Workspace Information</h2>
        <div className={styles.infoGrid}>
          <div className={styles.infoItem}>
            <div className={styles.infoLabel}>Workspace ID</div>
            <div className={styles.infoValue}>{tenantInfo?.id || "N/A"}</div>
          </div>
          {tenantInfo?.name && (
            <div className={styles.infoItem}>
              <div className={styles.infoLabel}>Workspace Name</div>
              <div className={styles.infoValue}>{tenantInfo.name}</div>
            </div>
          )}
          {tenantInfo?.state && (
            <div className={styles.infoItem}>
              <div className={styles.infoLabel}>State</div>
              <div className={styles.infoValue}>{tenantInfo.state}</div>
            </div>
          )}
        </div>
      </div>

      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Management</h2>
        <div className={styles.actionGrid}>
          {isTenantOwner && (
            <div
              className={styles.actionCard}
              onClick={() => router.push("/admin/invitations")}
            >
              <div className={styles.actionIcon}>📧</div>
              <div className={styles.actionTitle}>Manage Invitations</div>
              <div className={styles.actionDescription}>
                Invite new members to your workspace
              </div>
            </div>
          )}

          <div className={styles.actionCard} onClick={() => router.push("/admin/members")}>
            <div className={styles.actionIcon}>👥</div>
            <div className={styles.actionTitle}>View Members</div>
            <div className={styles.actionDescription}>
              See all workspace members
            </div>
            <div className={styles.comingSoon}>Coming Soon</div>
          </div>

          <div className={styles.actionCard} onClick={() => router.push("/dashboard")}>
            <div className={styles.actionIcon}>📊</div>
            <div className={styles.actionTitle}>Dashboard</div>
            <div className={styles.actionDescription}>
              Access the control panel
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

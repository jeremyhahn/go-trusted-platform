"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getUserFromToken } from "@/utils/jwt";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { getCookie } from "@/utils/cookie";
import styles from "./TenantPage.module.css";
import { useLogout } from "@/hooks/use-logout";

interface TenantInfo {
  id: string;
  name?: string;
  member_count: number;
}

/**
 * loadTenantInfo reads the tenant of the signed-in user. With no tenant it
 * returns no info (the empty state); when the read fails it still returns
 * the tenant ID with the error.
 */
async function loadTenantInfo(
  tenantId: string | null | undefined
): Promise<{ info: TenantInfo | null; error: string | null }> {
  if (!tenantId) {
    return { info: null, error: null };
  }
  try {
    const baseUrl = getBaseUrl();
    const jwt = getCookie("jwt");

    const response = await fetch(`${baseUrl}/api/v1/tenant`, {
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
    });

    if (!response.ok) {
      throw new Error("Failed to fetch tenant information");
    }

    const data = await response.json();
    return {
      info: {
        id: tenantId,
        name: data.name,
        member_count: data.member_count || 0,
      },
      error: null,
    };
  } catch (error) {
    return {
      info: { id: tenantId, member_count: 0 },
      error:
        error instanceof Error ? error.message : "Failed to fetch tenant info",
    };
  }
}

export default function TenantPage() {
  const router = useRouter();
  const [tenantInfo, setTenantInfo] = useState<TenantInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isTenantOwner, setIsTenantOwner] = useState(false);

  // The effect reads the session, then settles the tenant read into state
  // from its promise callback (no synchronous setState in the effect).
  useEffect(() => {
    const user = getUserFromToken();
    if (!user) {
      router.push("/auth/webauthn");
      return;
    }

    let active = true;
    void loadTenantInfo(user.tenantId).then((result) => {
      if (!active) {
        return;
      }
      setIsTenantOwner(user.isTenantOwner);
      setTenantInfo(result.info);
      setError(result.error);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [router]);

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
          <div className={styles.infoItem}>
            <div className={styles.infoLabel}>Members</div>
            <div className={styles.infoValue}>
              {tenantInfo?.member_count || 0}
            </div>
          </div>
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

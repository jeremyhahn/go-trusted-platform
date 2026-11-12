"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getUserFromToken } from "@/utils/jwt";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { getCookie } from "@/utils/cookie";
import styles from "./InvitationsPage.module.css";

interface Invitation {
  id: string;
  email: string;
  role: string;
  expires_at: string;
  created_at: string;
  token: string;
}

type NotificationType = "success" | "error";

interface Notification {
  message: string;
  type: NotificationType;
}

/** loadInvitations reads the tenant's invitations; it throws on failure. */
async function loadInvitations(): Promise<Invitation[]> {
  const baseUrl = getBaseUrl();
  const jwt = getCookie("jwt");

  const response = await fetch(`${baseUrl}/api/v1/invitations`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  });

  if (!response.ok) {
    throw new Error("Failed to fetch invitations");
  }

  const data = await response.json();
  return data.invitations || [];
}

export default function InvitationsPage() {
  const router = useRouter();
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [loading, setLoading] = useState(false);
  const [fetchingInvitations, setFetchingInvitations] = useState(true);
  const [notification, setNotification] = useState<Notification | null>(null);
  const [isTenantOwner, setIsTenantOwner] = useState(false);

  const showNotification = (message: string, type: NotificationType) => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  // The effect reads the session, then settles the invitations read into
  // state from its promise callbacks (no synchronous setState in the
  // effect). A non-owner gets no read and the owner-only notice.
  useEffect(() => {
    const user = getUserFromToken();
    if (!user) {
      router.push("/auth/webauthn");
      return;
    }

    let active = true;
    const request = user.isTenantOwner
      ? loadInvitations()
      : Promise.resolve(null);
    void request.then(
      (list) => {
        if (!active) {
          return;
        }
        if (list === null) {
          setIsTenantOwner(false);
          setNotification({
            message: "Only tenant owners can manage invitations.",
            type: "error",
          });
        } else {
          setIsTenantOwner(true);
          setInvitations(list);
        }
        setFetchingInvitations(false);
      },
      (error: unknown) => {
        if (!active) {
          return;
        }
        setIsTenantOwner(true);
        setNotification({
          message:
            error instanceof Error ? error.message : "Failed to fetch invitations",
          type: "error",
        });
        setTimeout(() => setNotification(null), 5000);
        setFetchingInvitations(false);
      }
    );
    return () => {
      active = false;
    };
  }, [router]);

  const handleCreateInvitation = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      showNotification("Please enter an email address", "error");
      return;
    }

    setLoading(true);

    try {
      const baseUrl = getBaseUrl();
      const jwt = getCookie("jwt");

      const response = await fetch(`${baseUrl}/api/v1/invitations`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({ email, role }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to create invitation");
      }

      const data = await response.json();
      setInvitations([data.invitation, ...invitations]);
      setEmail("");
      setRole("member");
      showNotification("Invitation created successfully!", "success");
    } catch (error) {
      showNotification(
        error instanceof Error ? error.message : "Failed to create invitation",
        "error"
      );
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeInvitation = async (id: string) => {
    if (!confirm("Are you sure you want to revoke this invitation?")) {
      return;
    }

    try {
      const baseUrl = getBaseUrl();
      const jwt = getCookie("jwt");

      const response = await fetch(`${baseUrl}/api/v1/invitations/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${jwt}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to revoke invitation");
      }

      setInvitations(invitations.filter((inv) => inv.id !== id));
      showNotification("Invitation revoked successfully", "success");
    } catch (error) {
      showNotification(
        error instanceof Error ? error.message : "Failed to revoke invitation",
        "error"
      );
    }
  };

  const copyInvitationLink = (token: string) => {
    const baseUrl = window.location.origin;
    const invitationLink = `${baseUrl}/auth/webauthn?invitation=${token}`;
    navigator.clipboard.writeText(invitationLink);
    showNotification("Invitation link copied to clipboard!", "success");
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + " " + date.toLocaleTimeString();
  };

  if (!isTenantOwner) {
    return (
      <div className={styles.container}>
        <div className={styles.errorCard}>
          <h2 className={styles.errorTitle}>Access Denied</h2>
          <p className={styles.errorMessage}>
            Only tenant owners can manage invitations.
          </p>
          <button
            onClick={() => router.push("/admin/tenant")}
            className={styles.button}
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1 className={styles.title}>Manage Invitations</h1>
        <button
          onClick={() => router.push("/admin/tenant")}
          className={styles.linkButton}
        >
          Back to Dashboard
        </button>
      </div>

      {notification && (
        <div
          className={
            notification.type === "success"
              ? styles.successNotification
              : styles.errorNotification
          }
        >
          {notification.message}
        </div>
      )}

      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Create New Invitation</h2>
        <form onSubmit={handleCreateInvitation} className={styles.form}>
          <div className={styles.formGroup}>
            <label htmlFor="email" className={styles.label}>
              Email Address
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
              className={styles.input}
              required
            />
          </div>

          <div className={styles.formGroup}>
            <label htmlFor="role" className={styles.label}>
              Role
            </label>
            <select
              id="role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className={styles.select}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
              <option value="owner">Owner</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className={styles.button}
          >
            {loading ? "Creating..." : "Create Invitation"}
          </button>
        </form>
      </div>

      <div className={styles.card}>
        <h2 className={styles.cardTitle}>Pending Invitations</h2>
        {fetchingInvitations ? (
          <div className={styles.loading}>Loading invitations...</div>
        ) : invitations.length === 0 ? (
          <p className={styles.emptyMessage}>No pending invitations</p>
        ) : (
          <div className={styles.invitationsList}>
            {invitations.map((invitation) => (
              <div key={invitation.id} className={styles.invitationItem}>
                <div className={styles.invitationInfo}>
                  <div className={styles.invitationEmail}>
                    {invitation.email}
                  </div>
                  <div className={styles.invitationDetails}>
                    <span className={styles.role}>{invitation.role}</span>
                    <span className={styles.date}>
                      Expires: {formatDate(invitation.expires_at)}
                    </span>
                  </div>
                </div>
                <div className={styles.invitationActions}>
                  <button
                    onClick={() => copyInvitationLink(invitation.token)}
                    className={styles.copyButton}
                    title="Copy invitation link"
                  >
                    Copy Link
                  </button>
                  <button
                    onClick={() => handleRevokeInvitation(invitation.id)}
                    className={styles.revokeButton}
                    title="Revoke invitation"
                  >
                    Revoke
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

"use client";

import { Suspense, useEffect } from "react";
import { useSearchParams } from "next/navigation";

import { useLocalLogout, useLogout } from "@/hooks/use-logout";
import styles from "../protected/ProtectedPage.module.css";

// useLogout routes here with revocation=failed when the server did not
// confirm the sign-out (#646). The bearer is still in place then, so the
// operator can retry the revocation or knowingly drop only this browser's
// copy of the session.
function LogoutFlow() {
  const logout = useLogout();
  const localLogout = useLocalLogout();
  const failed = useSearchParams().get("revocation") === "failed";

  useEffect(() => {
    if (!failed) {
      void logout();
    }
  }, [failed, logout]);

  if (failed) {
    return (
      <div className={styles.container}>
        <div className={styles.card}>
          <h2 className={styles.title}>Sign-out not confirmed</h2>
          <p className={styles.message}>
            The server did not confirm your sign-out. Your session may still be
            valid on the server.
          </p>
          <button type="button" onClick={() => void logout()}>
            Retry sign-out
          </button>
          <button type="button" onClick={() => localLogout()}>
            Sign out of this browser only
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.card}>
        <h2 className={styles.title}>Logging Out...</h2>
        <p className={styles.message}>
          You are being logged out. Please wait...
        </p>
      </div>
    </div>
  );
}

export default function LogoutPage() {
  return (
    <Suspense fallback={null}>
      <LogoutFlow />
    </Suspense>
  );
}

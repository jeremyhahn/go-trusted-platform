"use client";

import { useEffect } from "react";

import { useLogout } from "@/hooks/use-logout";
import styles from "../protected/ProtectedPage.module.css";

export default function LogoutPage() {
  const logout = useLogout();

  useEffect(() => {
    logout();
  }, [logout]);

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

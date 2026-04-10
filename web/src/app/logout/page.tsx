"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { deleteCookie } from "@/utils/cookie";
import styles from "../protected/ProtectedPage.module.css";

export default function LogoutPage() {
  const router = useRouter();

  useEffect(() => {
    deleteCookie("uid");
    deleteCookie("jwt");
    router.push("/auth/webauthn");
  }, [router]);

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

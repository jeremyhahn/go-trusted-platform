import { redirect } from "next/navigation";

export default function Home() {
  // TODO: Check authentication status
  // If user is authenticated, redirect to dashboard
  // Otherwise, redirect to login

  // For now, redirect to auth page
  // Once auth is implemented, use:
  // const isAuthenticated = checkAuth();
  // if (isAuthenticated) {
  //   redirect("/dashboard");
  // }

  redirect("/auth/webauthn");
}

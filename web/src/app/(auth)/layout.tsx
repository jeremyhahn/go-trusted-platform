import * as React from "react";
import { TrustedPlatformBrandIcon } from "@/components/brand/trusted-platform-brand-icon";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-b from-background to-muted/20 p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Logo and Title */}
        <div className="flex flex-col items-center space-y-2 text-center">
          <TrustedPlatformBrandIcon className="h-16 w-16" />
          <h1 className="text-2xl font-bold tracking-tight">
            Trusted Platform
          </h1>
          <p className="text-sm text-muted-foreground">
            Secure Computing Platform
          </p>
        </div>

        {/* Auth Form */}
        <div className="w-full">{children}</div>

        {/* Footer */}
        <div className="text-center text-xs text-muted-foreground">
          <p>
            By continuing, you agree to our Terms of Service and Privacy Policy
          </p>
        </div>
      </div>
    </div>
  );
}

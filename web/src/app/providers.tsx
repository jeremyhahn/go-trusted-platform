"use client";

/**
 * Application Providers
 *
 * Wraps the application with all necessary context providers:
 * - PlatformProvider: SDK client for API access
 * - ThemeProvider: Dark/light theme support
 * - Toaster: Toast notifications
 *
 * The PlatformProvider makes the SDK client available throughout the app
 * via React hooks like usePlatform(), useDevice(), useCA(), etc.
 */

import * as React from "react";
import { PlatformProvider } from "trusted-platform-sdk";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/toaster";

/**
 * Get the base URL for API requests
 * - In browser: use the proxy path configured in next.config.mjs
 * - In SSR: use the full backend URL from environment
 */
function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    return "/api";
  }
  return process.env.API_URL || "https://localhost:8443/api";
}

/**
 * Props for the Providers component
 */
interface ProvidersProps {
  children: React.ReactNode;
}

/**
 * Root providers component
 *
 * Combines all application-level providers into a single component
 * for cleaner layout structure.
 *
 * @example
 * ```tsx
 * // In layout.tsx
 * export default function RootLayout({ children }) {
 *   return (
 *     <html lang="en">
 *       <body>
 *         <Providers>{children}</Providers>
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 */
export function Providers({ children }: ProvidersProps) {
  return (
    <PlatformProvider
      config={{
        baseUrl: getBaseUrl(),
        credentials: "include",
        retry: {
          maxRetries: 3,
          initialDelayMs: 1000,
          retryableStatuses: [408, 429, 500, 502, 503, 504],
        },
        timeout: {
          requestTimeoutMs: 30000,
          connectionTimeoutMs: 5000,
        },
      }}
    >
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        {children}
        <Toaster />
      </ThemeProvider>
    </PlatformProvider>
  );
}

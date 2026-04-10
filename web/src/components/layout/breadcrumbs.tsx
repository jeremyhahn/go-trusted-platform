"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight } from "lucide-react";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

/**
 * Breadcrumbs component that auto-generates from the current pathname
 *
 * Features:
 * - Automatically extracts path segments from URL
 * - Formats segment labels (capitalizes, replaces hyphens)
 * - Links all segments except the last (current page)
 * - Uses Separator component between items
 *
 * @example
 * ```tsx
 * // On page /iam/users/123
 * <Breadcrumbs />
 * // Renders: Home > IAM > Users > 123
 * ```
 */
export function Breadcrumbs() {
  const pathname = usePathname();

  const segments = React.useMemo(() => {
    // Remove leading/trailing slashes and split
    const paths = pathname.split("/").filter(Boolean);

    // Build breadcrumb items with accumulated paths
    return paths.map((segment, index) => {
      const href = "/" + paths.slice(0, index + 1).join("/");
      const label = formatSegment(segment);
      const isLast = index === paths.length - 1;

      return {
        label,
        href,
        isLast,
      };
    });
  }, [pathname]);

  // Don't render if on home page
  if (pathname === "/" || segments.length === 0) {
    return null;
  }

  return (
    <nav aria-label="Breadcrumb" className="flex items-center space-x-1 text-sm">
      <Link
        href="/"
        className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-50"
      >
        Home
      </Link>

      {segments.map((segment, index) => (
        <React.Fragment key={segment.href}>
          <ChevronRight className="h-4 w-4 text-neutral-400" />
          {segment.isLast ? (
            <span className="font-medium text-neutral-900 dark:text-neutral-50">
              {segment.label}
            </span>
          ) : (
            <Link
              href={segment.href}
              className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-50"
            >
              {segment.label}
            </Link>
          )}
        </React.Fragment>
      ))}
    </nav>
  );
}

/**
 * Format a URL segment into a readable label
 * - Capitalizes each word
 * - Replaces hyphens and underscores with spaces
 * - Handles common acronyms (IAM, API, etc.)
 */
function formatSegment(segment: string): string {
  // Common acronyms that should be uppercase
  const acronyms = ["iam", "api", "ca", "kms", "sdn", "dns", "pxe", "vm", "vms"];

  // Replace hyphens/underscores with spaces and split
  const words = segment.replace(/[-_]/g, " ").split(" ");

  // Capitalize each word
  const formatted = words
    .map((word) => {
      const lower = word.toLowerCase();
      // If it's an acronym, return uppercase
      if (acronyms.includes(lower)) {
        return lower.toUpperCase();
      }
      // Otherwise capitalize first letter
      return word.charAt(0).toUpperCase() + word.slice(1);
    })
    .join(" ");

  return formatted;
}

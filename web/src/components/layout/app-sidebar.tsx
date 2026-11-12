"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLogout } from "@/hooks/use-logout";
import { useSignedInIdentity } from "@/hooks/use-signed-in-identity";
import {
  LayoutDashboard,
  Shield,
  Building2,
  Lock,
  Cpu,
  Server,
  Network,
  Settings,
  ChevronRight,
  LogOut,
  User,
  Database,
  HardDrive,
  Key,
  FileCheck,
  Globe,
  Radio,
  Activity,
  Fingerprint,
  PackageCheck,
} from "lucide-react";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
  SidebarCollapsible,
  SidebarCollapsibleTrigger,
  SidebarCollapsibleContent,
  SidebarRail,
} from "@/components/ui/sidebar";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { TrustedPlatformBrandIcon } from "@/components/brand/trusted-platform-brand-icon";

// Navigation structure - covers all go-trusted-platform, go-dragondb, go-trusted-ca services
const navigation = [
  { title: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  {
    title: "Identity & Access",
    icon: Shield,
    children: [
      { title: "Users", href: "/iam/users" },
      { title: "Roles", href: "/iam/roles" },
      { title: "Groups", href: "/iam/groups" },
      { title: "Policies", href: "/iam/policies" },
      { title: "Applications", href: "/iam/apps" },
      { title: "API Tokens", href: "/iam/tokens" },
    ],
  },
  {
    title: "Tenant",
    icon: Building2,
    children: [
      { title: "Overview", href: "/tenant" },
      { title: "Members", href: "/tenant/members" },
      { title: "Invitations", href: "/tenant/invitations" },
      { title: "Quotas", href: "/tenant/quotas" },
    ],
  },
  {
    title: "Security",
    icon: Lock,
    children: [
      { title: "Certificates", href: "/ca/certificates" },
      { title: "Certificate Requests", href: "/ca/requests" },
      { title: "CA Bundle", href: "/ca/bundle" },
      { title: "CRL", href: "/ca/crl" },
      { title: "Key Management", href: "/kms" },
      { title: "Key Encryption", href: "/kms/encrypt" },
    ],
  },
  {
    title: "Attestation",
    icon: FileCheck,
    children: [
      { title: "Manifests", href: "/attestation/manifests" },
      { title: "Quotes", href: "/attestation/quotes" },
      { title: "Verification", href: "/attestation/verify" },
      { title: "Event Logs", href: "/attestation/eventlogs" },
    ],
  },
  {
    title: "TPM",
    icon: Fingerprint,
    children: [
      { title: "Status", href: "/tpm/status" },
      { title: "Keys", href: "/tpm/keys" },
      { title: "PCR Banks", href: "/tpm/pcrs" },
      { title: "Event Log", href: "/tpm/eventlog" },
      { title: "Quote / Attestation", href: "/tpm/quote" },
      { title: "Lockout", href: "/tpm/lockout" },
      { title: "NVRAM", href: "/tpm/nvram" },
      { title: "Seal/Unseal", href: "/tpm/seal" },
      { title: "Credential / Random", href: "/tpm/credential" },
    ],
  },
  {
    title: "Devices",
    icon: Cpu,
    children: [
      { title: "All Devices", href: "/devices" },
      { title: "Device Profiles", href: "/devices/profiles" },
      { title: "Device Templates", href: "/devices/templates" },
      { title: "vTPM Bundles", href: "/devices/vtpm" },
      { title: "IDevID/IAK", href: "/devices/idevid" },
    ],
  },
  {
    title: "Provisioning",
    icon: PackageCheck,
    children: [
      { title: "Sessions", href: "/provisioning/sessions" },
    ],
  },
  {
    title: "Compute",
    icon: Server,
    children: [
      { title: "Virtual Machines", href: "/compute/vms" },
      { title: "Containers", href: "/compute/containers" },
      { title: "Snapshots", href: "/compute/snapshots" },
      { title: "Images", href: "/compute/images" },
    ],
  },
  {
    title: "Networking",
    icon: Network,
    children: [
      { title: "SDN Bridges", href: "/networking/sdn" },
      { title: "Network Zones", href: "/networking/zones" },
      { title: "IPAM Pools", href: "/networking/ipam" },
      { title: "Ports", href: "/networking/ports" },
      { title: "Flows", href: "/networking/flows" },
      { title: "VLANs", href: "/networking/vlans" },
      { title: "DNS Zones", href: "/networking/dns" },
      { title: "Overlays", href: "/networking/overlays" },
      { title: "Gateway", href: "/networking/gateway" },
      { title: "VPN", href: "/networking/vpn" },
      { title: "PXE Boot", href: "/networking/pxe" },
    ],
  },
  {
    title: "Data Storage",
    icon: Database,
    children: [
      { title: "Object Storage", href: "/storage/objects" },
      { title: "Key-Value Store", href: "/storage/kv" },
      { title: "Time Series", href: "/storage/timeseries" },
      { title: "Vector Database", href: "/storage/vector" },
      { title: "Backup & Restore", href: "/storage/backup" },
    ],
  },
  {
    title: "Platform",
    icon: Settings,
    children: [
      { title: "Health", href: "/platform/health" },
      { title: "Services", href: "/platform/services" },
      { title: "Configuration", href: "/platform/config" },
      { title: "Events", href: "/platform/events" },
      { title: "Metrics", href: "/platform/metrics" },
      { title: "Logs", href: "/platform/logs" },
    ],
  },
];

type AppSidebarProps = React.ComponentPropsWithoutRef<typeof Sidebar>;

/**
 * Main application sidebar with navigation
 *
 * Features:
 * - Hierarchical navigation with collapsible groups
 * - Active state tracking based on pathname
 * - Account dropdown in the footer showing the signed-in account from the
 *   session claims
 * - Responsive behavior (sheet on mobile, collapsible on desktop)
 *
 * @example
 * ```tsx
 * <SidebarProvider>
 *   <AppSidebar />
 *   <main>...</main>
 * </SidebarProvider>
 * ```
 */
export function AppSidebar(props: AppSidebarProps) {
  const pathname = usePathname();
  const handleLogout = useLogout();
  const identity = useSignedInIdentity();

  // Check if a navigation item or its children are active
  const isActive = (href: string) => pathname === href;
  const hasActiveChild = (children?: { href: string }[]) =>
    children?.some((child) => isActive(child.href)) ?? false;

  return (
    <Sidebar {...props}>
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-2">
          <TrustedPlatformBrandIcon className="h-7 w-7 shrink-0" />
          <span className="text-lg font-semibold">Trusted Platform</span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarMenu>
          {navigation.map((item) => {
            const Icon = item.icon;

            // If item has no children, render as single link
            if (!item.children) {
              return (
                <SidebarMenuItem key={item.href}>
                  <SidebarMenuButton
                    asChild
                    isActive={isActive(item.href)}
                    tooltip={item.title}
                  >
                    <Link href={item.href}>
                      <Icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              );
            }

            // If item has children, render as collapsible group
            const defaultOpen = hasActiveChild(item.children);
            return (
              <SidebarCollapsible key={item.title} defaultOpen={defaultOpen}>
                <SidebarMenuItem>
                  <SidebarCollapsibleTrigger asChild>
                    <SidebarMenuButton tooltip={item.title}>
                      <Icon />
                      <span>{item.title}</span>
                      <ChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90" />
                    </SidebarMenuButton>
                  </SidebarCollapsibleTrigger>
                  <SidebarCollapsibleContent>
                    <SidebarMenuSub>
                      {item.children.map((child) => (
                        <SidebarMenuSubItem key={child.href}>
                          <SidebarMenuSubButton
                            asChild
                            isActive={isActive(child.href)}
                          >
                            <Link href={child.href}>
                              <span>{child.title}</span>
                            </Link>
                          </SidebarMenuSubButton>
                        </SidebarMenuSubItem>
                      ))}
                    </SidebarMenuSub>
                  </SidebarCollapsibleContent>
                </SidebarMenuItem>
              </SidebarCollapsible>
            );
          })}
        </SidebarMenu>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton
                  size="lg"
                  className="data-[state=open]:bg-neutral-200 dark:data-[state=open]:bg-neutral-800"
                  data-testid="sidebar-account-menu"
                  aria-label="Account menu"
                >
                  <Avatar className="h-8 w-8">
                    <AvatarFallback className="bg-primary text-primary-foreground">
                      {identity?.initial}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex min-w-0 flex-col items-start text-left text-sm">
                    <span
                      className="w-full truncate font-medium"
                      data-testid="sidebar-account-email"
                    >
                      {identity?.email}
                    </span>
                    {identity?.tenantId && (
                      <span className="w-full truncate text-xs text-neutral-500 dark:text-neutral-400">
                        {identity.tenantId}
                      </span>
                    )}
                  </div>
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" className="w-56">
                <DropdownMenuLabel>My Account</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link href="/profile" className="cursor-pointer">
                    <User className="mr-2 h-4 w-4" />
                    <span>Profile</span>
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link href="/settings" className="cursor-pointer">
                    <Settings className="mr-2 h-4 w-4" />
                    <span>Settings</span>
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={handleLogout}
                  className="cursor-pointer text-destructive focus:text-destructive"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Log out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}

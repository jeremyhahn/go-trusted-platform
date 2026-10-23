"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Search, LogOut, User, Settings } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Input } from "@/components/ui/input";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Breadcrumbs } from "./breadcrumbs";
import { ThemeToggle } from "@/components/theme-toggle";
import { useLogout } from "@/hooks/use-logout";
import { useSignedInIdentity } from "@/hooks/use-signed-in-identity";

/**
 * Top header component for the application
 *
 * Features:
 * - SidebarTrigger for mobile navigation
 * - Breadcrumb navigation
 * - Search input
 * - Dark mode toggle using next-themes
 * - User dropdown menu showing the signed-in account from the session claims
 */
export function Header() {
  const router = useRouter();
  const handleLogout = useLogout();
  const identity = useSignedInIdentity();

  return (
    <header className="sticky top-0 z-50 flex h-16 items-center gap-4 border-b bg-background px-6">
      {/* Mobile sidebar trigger */}
      <div className="md:hidden">
        <SidebarTrigger />
        <Separator orientation="vertical" className="h-6 ml-2" />
      </div>

      {/* Breadcrumbs */}
      <div className="hidden md:flex flex-1 items-center">
        <Breadcrumbs />
      </div>

      {/* Search */}
      <div className="flex flex-1 md:flex-initial md:w-64 items-center">
        <div className="relative w-full">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search..."
            className="pl-8 w-full"
          />
        </div>
      </div>

      {/* Right side actions */}
      <div className="flex items-center gap-2">
        {/* Dark mode toggle */}
        <ThemeToggle />

        {/* User dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="relative h-9 w-9 rounded-full"
              data-testid="header-account-menu"
              aria-label="Account menu"
            >
              <Avatar className="h-9 w-9">
                <AvatarFallback className="bg-primary text-primary-foreground">
                  {identity?.initial}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-56" align="end" forceMount>
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p
                  className="text-sm font-medium leading-none"
                  data-testid="header-account-email"
                >
                  {identity?.email}
                </p>
                {identity?.tenantId && (
                  <p className="text-xs leading-none text-muted-foreground">
                    {identity.tenantId}
                  </p>
                )}
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => router.push("/profile")}>
              <User className="mr-2 h-4 w-4" />
              <span>Profile</span>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => router.push("/settings")}>
              <Settings className="mr-2 h-4 w-4" />
              <span>Settings</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleLogout}
              className="text-destructive focus:text-destructive"
            >
              <LogOut className="mr-2 h-4 w-4" />
              <span>Log out</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

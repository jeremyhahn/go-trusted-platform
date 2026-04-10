"use client";

import * as React from "react";
import { Check, ChevronsUpDown, Crown, Shield, User, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import type { TenantRole } from "@/types/tenant";

interface MemberRoleEditorProps {
  currentRole: TenantRole;
  disabled?: boolean;
  onRoleChange: (role: TenantRole) => void;
}

const roleConfig: Record<TenantRole, { label: string; description: string; icon: typeof Crown }> = {
  owner: {
    label: "Owner",
    description: "Full access to all settings",
    icon: Crown,
  },
  admin: {
    label: "Admin",
    description: "Can manage members and settings",
    icon: Shield,
  },
  member: {
    label: "Member",
    description: "Basic access to resources",
    icon: User,
  },
  viewer: {
    label: "Viewer",
    description: "Read-only access to resources",
    icon: Eye,
  },
};

const roles: TenantRole[] = ["owner", "admin", "member", "viewer"];

export function MemberRoleEditor({
  currentRole,
  disabled,
  onRoleChange,
}: MemberRoleEditorProps) {
  const [open, setOpen] = React.useState(false);
  const [selectedRole, setSelectedRole] = React.useState<TenantRole>(currentRole);

  const handleRoleSelect = (role: TenantRole) => {
    setSelectedRole(role);
    onRoleChange(role);
    setOpen(false);
  };

  const CurrentIcon = roleConfig[selectedRole].icon;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-label="Select role"
          className="w-[180px] justify-between"
          disabled={disabled}
        >
          <span className="flex items-center gap-2">
            <CurrentIcon className="h-4 w-4" />
            {roleConfig[selectedRole].label}
          </span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[240px] p-0" align="start">
        <Command>
          <CommandList>
            <CommandEmpty>No role found.</CommandEmpty>
            <CommandGroup>
              {roles.map((role) => {
                const Icon = roleConfig[role].icon;
                return (
                  <CommandItem
                    key={role}
                    onSelect={() => handleRoleSelect(role)}
                  >
                    <div className="flex items-start gap-3 flex-1">
                      <Icon className="h-4 w-4 mt-0.5" />
                      <div className="flex-1 space-y-1">
                        <p className="text-sm font-medium leading-none">
                          {roleConfig[role].label}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {roleConfig[role].description}
                        </p>
                      </div>
                    </div>
                    <Check
                      className={cn(
                        "ml-2 h-4 w-4",
                        selectedRole === role ? "opacity-100" : "opacity-0"
                      )}
                    />
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

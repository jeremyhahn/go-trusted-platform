'use client';

/**
 * Role Picker Component
 *
 * Multi-select role picker with badges and dropdown.
 */

import React, { useState } from 'react';
import { LegacyRole } from '@/types/iam';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { ScrollArea } from '@/components/ui/scroll-area';
import { X, Plus } from 'lucide-react';
import { cn } from '@/lib/utils';

interface RolePickerProps {
  roles: LegacyRole[];
  selectedRoleIds: string[];
  onChange: (roleIds: string[]) => void;
  disabled?: boolean;
  className?: string;
}

/**
 * Role picker component for selecting multiple roles
 */
export function RolePicker({
  roles,
  selectedRoleIds,
  onChange,
  disabled = false,
  className,
}: RolePickerProps) {
  const [open, setOpen] = useState(false);

  const selectedRoles = roles.filter((role) =>
    selectedRoleIds.includes(role.id)
  );

  const handleToggle = (roleId: string) => {
    if (selectedRoleIds.includes(roleId)) {
      onChange(selectedRoleIds.filter((id) => id !== roleId));
    } else {
      onChange([...selectedRoleIds, roleId]);
    }
  };

  const handleRemove = (roleId: string) => {
    onChange(selectedRoleIds.filter((id) => id !== roleId));
  };

  return (
    <div className={cn('space-y-2', className)}>
      {/* Selected roles badges */}
      {selectedRoles.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {selectedRoles.map((role) => (
            <Badge key={role.id} variant="secondary" className="pr-1">
              {role.name}
              {!disabled && (
                <button
                  type="button"
                  onClick={() => handleRemove(role.id)}
                  className="ml-1 rounded-full hover:bg-secondary-foreground/20 p-0.5"
                >
                  <X className="h-3 w-3" />
                  <span className="sr-only">Remove {role.name}</span>
                </button>
              )}
            </Badge>
          ))}
        </div>
      )}

      {/* Add role button */}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={disabled}
            className="w-full justify-start"
          >
            <Plus className="mr-2 h-4 w-4" />
            {selectedRoles.length === 0
              ? 'Select roles'
              : 'Add more roles'}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[300px] p-0" align="start">
          <ScrollArea className="h-[300px]">
            <div className="p-4 space-y-2">
              {roles.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No roles available
                </p>
              ) : (
                roles.map((role) => {
                  const isSelected = selectedRoleIds.includes(role.id);
                  return (
                    <div
                      key={role.id}
                      className="flex items-start space-x-2 p-2 rounded-md hover:bg-accent cursor-pointer"
                      onClick={() => handleToggle(role.id)}
                    >
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => handleToggle(role.id)}
                        className="mt-1"
                      />
                      <div className="flex-1 space-y-1">
                        <p className="text-sm font-medium leading-none">
                          {role.name}
                        </p>
                        {role.description && (
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {role.description}
                          </p>
                        )}
                        <p className="text-xs text-muted-foreground">
                          {role.permissions.length} permission
                          {role.permissions.length !== 1 ? 's' : ''}
                        </p>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </ScrollArea>
        </PopoverContent>
      </Popover>
    </div>
  );
}

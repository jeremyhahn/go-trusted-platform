'use client';

/**
 * Permission Tree Component
 *
 * Hierarchical checkbox tree for managing permissions grouped by resource.
 */

import React, { useMemo } from 'react';
import { Permission, PermissionGroup } from '@/types/iam';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ChevronRight, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PermissionTreeProps {
  permissions: Permission[];
  selectedPermissionIds: string[];
  onChange: (permissionIds: string[]) => void;
  disabled?: boolean;
  className?: string;
}

/**
 * Groups permissions by resource
 */
function groupPermissionsByResource(permissions: Permission[]): PermissionGroup[] {
  const groups = new Map<string, Permission[]>();

  permissions.forEach((permission) => {
    const resource = permission.resource;
    if (!groups.has(resource)) {
      groups.set(resource, []);
    }
    groups.get(resource)!.push(permission);
  });

  return Array.from(groups.entries())
    .map(([resource, perms]) => ({
      resource,
      permissions: perms.sort((a, b) => a.action.localeCompare(b.action)),
    }))
    .sort((a, b) => a.resource.localeCompare(b.resource));
}

/**
 * Permission tree component for selecting permissions by resource groups
 */
export function PermissionTree({
  permissions,
  selectedPermissionIds,
  onChange,
  disabled = false,
  className,
}: PermissionTreeProps) {
  const groups = useMemo(
    () => groupPermissionsByResource(permissions),
    [permissions]
  );

  const [expandedGroups, setExpandedGroups] = React.useState<Set<string>>(
    new Set(groups.map((g) => g.resource))
  );

  const toggleGroup = (resource: string) => {
    const newExpanded = new Set(expandedGroups);
    if (newExpanded.has(resource)) {
      newExpanded.delete(resource);
    } else {
      newExpanded.add(resource);
    }
    setExpandedGroups(newExpanded);
  };

  const handleTogglePermission = (permissionId: string) => {
    if (selectedPermissionIds.includes(permissionId)) {
      onChange(selectedPermissionIds.filter((id) => id !== permissionId));
    } else {
      onChange([...selectedPermissionIds, permissionId]);
    }
  };

  const handleToggleGroup = (group: PermissionGroup, checked: boolean) => {
    const groupPermissionIds = group.permissions.map((p) => p.id);

    if (checked) {
      // Add all permissions from this group
      const newSelected = new Set([
        ...selectedPermissionIds,
        ...groupPermissionIds,
      ]);
      onChange(Array.from(newSelected));
    } else {
      // Remove all permissions from this group
      onChange(
        selectedPermissionIds.filter((id) => !groupPermissionIds.includes(id))
      );
    }
  };

  const isGroupSelected = (group: PermissionGroup): boolean => {
    return group.permissions.every((p) => selectedPermissionIds.includes(p.id));
  };

  const isGroupIndeterminate = (group: PermissionGroup): boolean => {
    const selectedCount = group.permissions.filter((p) =>
      selectedPermissionIds.includes(p.id)
    ).length;
    return selectedCount > 0 && selectedCount < group.permissions.length;
  };

  if (permissions.length === 0) {
    return (
      <div className={cn('text-center py-8', className)}>
        <p className="text-sm text-muted-foreground">No permissions available</p>
      </div>
    );
  }

  return (
    <ScrollArea className={cn('h-[400px] border rounded-md', className)}>
      <div className="p-4 space-y-2">
        {groups.map((group) => {
          const isExpanded = expandedGroups.has(group.resource);
          const isSelected = isGroupSelected(group);
          const isIndeterminate = isGroupIndeterminate(group);

          return (
            <Collapsible
              key={group.resource}
              open={isExpanded}
              onOpenChange={() => toggleGroup(group.resource)}
            >
              <div className="space-y-2">
                {/* Resource group header */}
                <div className="flex items-center space-x-2 p-2 rounded-md hover:bg-accent">
                  <CollapsibleTrigger asChild>
                    <button
                      type="button"
                      className="flex items-center flex-1 text-left"
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 mr-2" />
                      ) : (
                        <ChevronRight className="h-4 w-4 mr-2" />
                      )}
                      <span className="font-medium text-sm">
                        {group.resource}
                      </span>
                      <span className="ml-2 text-xs text-muted-foreground">
                        ({group.permissions.length})
                      </span>
                    </button>
                  </CollapsibleTrigger>
                  <Checkbox
                    checked={isSelected ? true : isIndeterminate ? 'indeterminate' : false}
                    onCheckedChange={(checked) =>
                      handleToggleGroup(group, !!checked)
                    }
                    disabled={disabled}
                    aria-label={`Select all ${group.resource} permissions`}
                  />
                </div>

                {/* Permission items */}
                <CollapsibleContent className="space-y-1 ml-6">
                  {group.permissions.map((permission) => (
                    <div
                      key={permission.id}
                      className="flex items-start space-x-2 p-2 rounded-md hover:bg-accent cursor-pointer"
                      onClick={() => handleTogglePermission(permission.id)}
                    >
                      <Checkbox
                        checked={selectedPermissionIds.includes(permission.id)}
                        onCheckedChange={() =>
                          handleTogglePermission(permission.id)
                        }
                        disabled={disabled}
                        className="mt-1"
                      />
                      <div className="flex-1 space-y-1">
                        <Label
                          htmlFor={permission.id}
                          className="text-sm font-medium leading-none cursor-pointer"
                        >
                          {permission.action}
                        </Label>
                        {permission.description && (
                          <p className="text-xs text-muted-foreground">
                            {permission.description}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </CollapsibleContent>
              </div>
            </Collapsible>
          );
        })}
      </div>
    </ScrollArea>
  );
}

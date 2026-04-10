'use client';

/**
 * User Form Component
 *
 * Form for creating and editing users with role assignment.
 */

import React, { useState } from 'react';
import { LegacyUser, CreateUserInput, UpdateUserInput, LegacyRole } from '@/types/iam';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { RolePicker } from './role-picker';

interface UserFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: CreateUserInput | UpdateUserInput) => void | Promise<void>;
  user?: LegacyUser;
  roles: LegacyRole[];
  loading?: boolean;
}

/**
 * User form component for create/edit operations
 */
export function UserForm({
  open,
  onOpenChange,
  onSubmit,
  user,
  roles,
  loading = false,
}: UserFormProps) {
  const isEdit = !!user;

  const [formData, setFormData] = useState<CreateUserInput>({
    name: user?.name || '',
    email: user?.email || '',
    password: '',
    roleIds: user?.roles.map((r) => r.id) || [],
    status: user?.status || 'active',
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  React.useEffect(() => {
    if (user) {
      setFormData({
        name: user.name,
        email: user.email,
        password: '',
        roleIds: user.roles.map((r) => r.id),
        status: user.status,
      });
    } else {
      setFormData({
        name: '',
        email: '',
        password: '',
        roleIds: [],
        status: 'active',
      });
    }
    setErrors({});
  }, [user, open]);

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!isEdit && !formData.password) {
      newErrors.password = 'Password is required';
    }

    if (!isEdit && formData.password && formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validate()) {
      return;
    }

    try {
      if (isEdit) {
        const updateData: UpdateUserInput = {
          name: formData.name,
          email: formData.email,
          roleIds: formData.roleIds,
          status: formData.status,
        };
        if (formData.password) {
          updateData.password = formData.password;
        }
        await onSubmit(updateData);
      } else {
        await onSubmit(formData as CreateUserInput);
      }
      onOpenChange(false);
    } catch (error) {
      console.error('Form submission error:', error);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[525px]">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit User' : 'Create User'}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? 'Update user information and role assignments.'
              : 'Add a new user to the system.'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="space-y-4 py-4">
            {/* Name */}
            <div className="space-y-2">
              <Label htmlFor="name">
                Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="John Doe"
                disabled={loading}
                className={errors.name ? 'border-destructive' : ''}
              />
              {errors.name && (
                <p className="text-sm text-destructive">{errors.name}</p>
              )}
            </div>

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="email">
                Email <span className="text-destructive">*</span>
              </Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) =>
                  setFormData({ ...formData, email: e.target.value })
                }
                placeholder="john@example.com"
                disabled={loading}
                className={errors.email ? 'border-destructive' : ''}
              />
              {errors.email && (
                <p className="text-sm text-destructive">{errors.email}</p>
              )}
            </div>

            {/* Password */}
            <div className="space-y-2">
              <Label htmlFor="password">
                Password {!isEdit && <span className="text-destructive">*</span>}
                {isEdit && (
                  <span className="text-muted-foreground text-xs ml-2">
                    (leave blank to keep current)
                  </span>
                )}
              </Label>
              <Input
                id="password"
                type="password"
                value={formData.password}
                onChange={(e) =>
                  setFormData({ ...formData, password: e.target.value })
                }
                placeholder={isEdit ? 'Enter new password' : 'Min. 8 characters'}
                disabled={loading}
                className={errors.password ? 'border-destructive' : ''}
              />
              {errors.password && (
                <p className="text-sm text-destructive">{errors.password}</p>
              )}
            </div>

            {/* Roles */}
            <div className="space-y-2">
              <Label>Roles</Label>
              <RolePicker
                roles={roles}
                selectedRoleIds={formData.roleIds || []}
                onChange={(roleIds) =>
                  setFormData({ ...formData, roleIds })
                }
                disabled={loading}
              />
            </div>

            {/* Status */}
            <div className="space-y-2">
              <Label htmlFor="status">Status</Label>
              <select
                id="status"
                value={formData.status}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    status: e.target.value as 'active' | 'disabled' | 'pending',
                  })
                }
                disabled={loading}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <option value="active">Active</option>
                <option value="pending">Pending</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Saving...' : isEdit ? 'Update User' : 'Create User'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

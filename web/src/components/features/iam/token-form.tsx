'use client';

/**
 * Token Form Component
 *
 * Form for generating API tokens with scopes and expiration.
 */

import React, { useState } from 'react';
import { CreateTokenInput } from '@/types/iam';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { X } from 'lucide-react';

interface TokenFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: CreateTokenInput) => void | Promise<void>;
  loading?: boolean;
}

// Common token scopes
const AVAILABLE_SCOPES = [
  { value: 'users:read', label: 'Read Users', description: 'View user information' },
  { value: 'users:write', label: 'Write Users', description: 'Create and modify users' },
  { value: 'roles:read', label: 'Read Roles', description: 'View role information' },
  { value: 'roles:write', label: 'Write Roles', description: 'Create and modify roles' },
  { value: 'tokens:read', label: 'Read Tokens', description: 'View token information' },
  { value: 'tokens:write', label: 'Write Tokens', description: 'Create and revoke tokens' },
  { value: 'admin', label: 'Admin', description: 'Full administrative access' },
];

/**
 * Token creation form component
 */
export function TokenForm({
  open,
  onOpenChange,
  onSubmit,
  loading = false,
}: TokenFormProps) {
  const [formData, setFormData] = useState<CreateTokenInput>({
    name: '',
    scopes: [],
    expiresAt: '',
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [customScope, setCustomScope] = useState('');

  React.useEffect(() => {
    if (open) {
      // Reset form when dialog opens
      const oneMonthFromNow = new Date();
      oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);

      setFormData({
        name: '',
        scopes: [],
        expiresAt: oneMonthFromNow.toISOString().split('T')[0],
      });
      setErrors({});
      setCustomScope('');
    }
  }, [open]);

  const validate = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Token name is required';
    }

    if (formData.scopes.length === 0) {
      newErrors.scopes = 'At least one scope is required';
    }

    if (formData.expiresAt) {
      const expirationDate = new Date(formData.expiresAt);
      if (expirationDate <= new Date()) {
        newErrors.expiresAt = 'Expiration date must be in the future';
      }
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
      await onSubmit(formData);
      onOpenChange(false);
    } catch (error) {
      console.error('Form submission error:', error);
    }
  };

  const toggleScope = (scope: string) => {
    if (formData.scopes.includes(scope)) {
      setFormData({
        ...formData,
        scopes: formData.scopes.filter((s) => s !== scope),
      });
    } else {
      setFormData({
        ...formData,
        scopes: [...formData.scopes, scope],
      });
    }
  };

  const addCustomScope = () => {
    if (customScope.trim() && !formData.scopes.includes(customScope.trim())) {
      setFormData({
        ...formData,
        scopes: [...formData.scopes, customScope.trim()],
      });
      setCustomScope('');
    }
  };

  const removeScope = (scope: string) => {
    setFormData({
      ...formData,
      scopes: formData.scopes.filter((s) => s !== scope),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[525px]">
        <DialogHeader>
          <DialogTitle>Generate API Token</DialogTitle>
          <DialogDescription>
            Create a new API token with specific scopes. The token secret will only be shown once.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="space-y-4 py-4">
            {/* Token Name */}
            <div className="space-y-2">
              <Label htmlFor="name">
                Token Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) =>
                  setFormData({ ...formData, name: e.target.value })
                }
                placeholder="My API Token"
                disabled={loading}
                className={errors.name ? 'border-destructive' : ''}
              />
              {errors.name && (
                <p className="text-sm text-destructive">{errors.name}</p>
              )}
            </div>

            {/* Expiration Date */}
            <div className="space-y-2">
              <Label htmlFor="expiresAt">Expiration Date</Label>
              <Input
                id="expiresAt"
                type="date"
                value={formData.expiresAt}
                onChange={(e) =>
                  setFormData({ ...formData, expiresAt: e.target.value })
                }
                disabled={loading}
                className={errors.expiresAt ? 'border-destructive' : ''}
              />
              {errors.expiresAt && (
                <p className="text-sm text-destructive">{errors.expiresAt}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Leave blank for no expiration
              </p>
            </div>

            {/* Selected Scopes */}
            {formData.scopes.length > 0 && (
              <div className="space-y-2">
                <Label>Selected Scopes</Label>
                <div className="flex flex-wrap gap-2 p-3 border rounded-md bg-muted/50">
                  {formData.scopes.map((scope) => (
                    <Badge key={scope} variant="secondary" className="pr-1">
                      {scope}
                      {!loading && (
                        <button
                          type="button"
                          onClick={() => removeScope(scope)}
                          className="ml-1 rounded-full hover:bg-secondary-foreground/20 p-0.5"
                        >
                          <X className="h-3 w-3" />
                          <span className="sr-only">Remove {scope}</span>
                        </button>
                      )}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Available Scopes */}
            <div className="space-y-2">
              <Label>
                Scopes <span className="text-destructive">*</span>
              </Label>
              <div className="space-y-2 max-h-[200px] overflow-y-auto p-3 border rounded-md">
                {AVAILABLE_SCOPES.map((scope) => (
                  <div
                    key={scope.value}
                    className="flex items-start space-x-2 p-2 rounded-md hover:bg-accent cursor-pointer"
                    onClick={(e) => {
                      // The checkbox toggles itself; its click (and the click
                      // its hidden form input re-dispatches) must not toggle
                      // the scope a second time.
                      if ((e.target as HTMLElement).closest('button, input')) {
                        return;
                      }
                      toggleScope(scope.value);
                    }}
                  >
                    <Checkbox
                      checked={formData.scopes.includes(scope.value)}
                      onCheckedChange={() => toggleScope(scope.value)}
                      disabled={loading}
                      className="mt-1"
                    />
                    <div className="flex-1 space-y-1">
                      <p className="text-sm font-medium leading-none">
                        {scope.label}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {scope.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
              {errors.scopes && (
                <p className="text-sm text-destructive">{errors.scopes}</p>
              )}
            </div>

            {/* Custom Scope */}
            <div className="space-y-2">
              <Label htmlFor="customScope">Custom Scope</Label>
              <div className="flex gap-2">
                <Input
                  id="customScope"
                  value={customScope}
                  onChange={(e) => setCustomScope(e.target.value)}
                  placeholder="custom:scope"
                  disabled={loading}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addCustomScope();
                    }
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={addCustomScope}
                  disabled={loading || !customScope.trim()}
                >
                  Add
                </Button>
              </div>
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
              {loading ? 'Generating...' : 'Generate Token'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

"use client";

import * as React from "react";
import { Mail, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { SendInvitationInput } from "@/types/tenant";

interface InvitationFormProps {
  onSubmit: (data: SendInvitationInput) => Promise<void>;
  /** The tenant's IAM role names; the server accepts only these (#1992). */
  roles: string[];
  /** The role lookup is still running. */
  rolesLoading?: boolean;
  /** The role lookup failed with this message; `roles` is then not the tenant's list. */
  rolesError?: string | null;
  /** Runs the role lookup again after a failure. */
  onRetryRoles?: () => void;
  trigger?: React.ReactNode;
}

/** The role an invitation starts with: "user" when listed, else the first. */
function defaultRole(roles: string[]): string {
  if (roles.includes("user")) return "user";
  return roles[0] ?? "";
}

export function InvitationForm({
  onSubmit,
  roles,
  rolesLoading = false,
  rolesError = null,
  onRetryRoles,
  trigger,
}: InvitationFormProps) {
  const rolesReady = !rolesLoading && !rolesError;
  const [open, setOpen] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<string>(() => defaultRole(roles));

  // Keep the picked role one the tenant has once the role list arrives.
  React.useEffect(() => {
    setRole((current) => (roles.includes(current) ? current : defaultRole(roles)));
  }, [roles]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !role || !rolesReady) return;

    setIsLoading(true);
    try {
      await onSubmit({ email, role });
      setOpen(false);
      setEmail("");
      setRole(defaultRole(roles));
    } catch (error) {
      console.error("Failed to send invitation:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpenChange = (newOpen: boolean) => {
    if (!isLoading) {
      setOpen(newOpen);
      if (!newOpen) {
        setEmail("");
        setRole(defaultRole(roles));
      }
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        {trigger || (
          <Button>
            <Mail className="h-4 w-4 mr-2" />
            Send Invitation
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Invite Team Member</DialogTitle>
            <DialogDescription>
              Send an invitation to join your tenant. They will receive an email
              with a link to accept.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="email">Email Address</Label>
              <Input
                id="email"
                type="email"
                placeholder="colleague@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isLoading}
                required
                autoComplete="email"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="role">Role</Label>
              {rolesLoading ? (
                <p className="text-sm text-muted-foreground" role="status">
                  Loading roles...
                </p>
              ) : rolesError ? (
                <div className="flex items-center justify-between gap-2" role="alert">
                  <p className="text-sm text-destructive">
                    Could not load this tenant&apos;s IAM roles: {rolesError}
                  </p>
                  {onRetryRoles && (
                    <Button type="button" variant="outline" size="sm" onClick={onRetryRoles}>
                      Retry
                    </Button>
                  )}
                </div>
              ) : (
                <select
                  id="role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  disabled={isLoading || roles.length === 0}
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {roles.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
              )}
              <p className="text-xs text-muted-foreground">
                {rolesReady && roles.length === 0
                  ? "This tenant has no IAM roles to invite with"
                  : "Choose one of this tenant's IAM roles for the new member"}
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOpenChange(false)}
              disabled={isLoading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isLoading || !email || !role || !rolesReady}>
              {isLoading ? (
                <>
                  <span className="animate-spin mr-2">⏳</span>
                  Sending...
                </>
              ) : (
                <>
                  <Send className="h-4 w-4 mr-2" />
                  Send Invitation
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

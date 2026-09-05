'use client';

/**
 * Token Display Component
 *
 * One-time display of newly generated API token with copy functionality.
 */

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Copy, Check, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TokenDisplayProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  token: string;
  tokenName: string;
}

/**
 * Token display component - shows token only once with copy functionality
 */
export function TokenDisplay({
  open,
  onOpenChange,
  token,
  tokenName,
}: TokenDisplayProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy token:', error);
    }
  };

  const handleClose = () => {
    setCopied(false);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[550px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Token Generated Successfully
          </DialogTitle>
          <DialogDescription>
            Your API token has been created. Make sure to copy it now as you won&apos;t be able to see it again.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Warning banner */}
          <div className="flex items-start gap-3 p-4 rounded-md bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800">
            <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-sm font-medium text-amber-900 dark:text-amber-100">
                Important: Save this token now
              </p>
              <p className="text-sm text-amber-700 dark:text-amber-300">
                This token will only be shown once. If you lose it, you&apos;ll need to generate a new one.
              </p>
            </div>
          </div>

          {/* Token Name */}
          <div className="space-y-2">
            <Label>Token Name</Label>
            <Input value={tokenName} readOnly className="font-mono" />
          </div>

          {/* Token Secret */}
          <div className="space-y-2">
            <Label htmlFor="token">Token Secret</Label>
            <div className="flex gap-2">
              <Input
                id="token"
                value={token}
                readOnly
                className="font-mono text-sm"
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={handleCopy}
                className={cn(
                  'flex-shrink-0',
                  copied && 'bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800'
                )}
              >
                {copied ? (
                  <>
                    <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
                    <span className="sr-only">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-4 w-4" />
                    <span className="sr-only">Copy token</span>
                  </>
                )}
              </Button>
            </div>
            {copied && (
              <p className="text-sm text-green-600 dark:text-green-400">
                Token copied to clipboard!
              </p>
            )}
          </div>

          {/* Usage Instructions */}
          <div className="space-y-2">
            <Label>Usage Example</Label>
            <div className="p-3 rounded-md bg-muted font-mono text-xs overflow-x-auto">
              <code>
                curl -H &quot;Authorization: Bearer {token.substring(0, 20)}...&quot; \<br />
                &nbsp;&nbsp;https://api.example.com/v1/users
              </code>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={handleClose}>
            I&apos;ve Saved the Token
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

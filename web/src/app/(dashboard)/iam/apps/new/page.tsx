'use client';

/**
 * Register OAuth Application page — minimal form that calls
 * iam.registerApp, then routes back to /iam/apps.
 */

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useIAM, useToast, useMutation } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';

export default function NewAppPage() {
  const router = useRouter();
  const { toast } = useToast();
  const iam = useIAM();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [grantTypes, setGrantTypes] = useState('client_credentials');

  const createMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant available');
      const uris = redirectUris
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const grants = grantTypes
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      return iam.registerApp({
        tenantId,
        name,
        redirectUris: uris.length > 0 ? uris : undefined,
        grantTypes: grants.length > 0 ? grants : undefined,
      });
    },
    {
      onSuccess: () => {
        toast({ title: 'Application registered', variant: 'success' });
        router.push('/iam/apps');
      },
      onError: (err) => {
        toast({
          title: 'Failed to register application',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      },
    },
  );

  if (authLoading) {
    return (
      <div className="container mx-auto py-6">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle>Register Application</CardTitle>
          <CardDescription>
            Register a new OAuth 2.0 client application.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Application Name *</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Application"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="grants">Grant Types (comma-separated)</Label>
            <Input
              id="grants"
              value={grantTypes}
              onChange={(e) => setGrantTypes(e.target.value)}
              placeholder="client_credentials, authorization_code"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="redirects">Redirect URIs (comma-separated)</Label>
            <Input
              id="redirects"
              value={redirectUris}
              onChange={(e) => setRedirectUris(e.target.value)}
              placeholder="https://app.example.com/callback"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => router.push('/iam/apps')}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(undefined)}
              disabled={!name || createMutation.isLoading}
            >
              {createMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Register Application
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

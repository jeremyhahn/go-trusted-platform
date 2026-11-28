'use client';

/**
 * Register OAuth Application page — minimal form that calls
 * iam.registerApp, then shows the one-time client secret until Done
 * routes back to /iam/apps.
 * Register Application is gated on the server's POST /api/v1/iam/tenants/{tenant}/apps capability (#2033).
 */

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useIAM, useToast, useMutation } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Loader2 } from 'lucide-react';
import { Gated } from '@/components/features/capabilities/gated';

// The server answers RegisterApp with a snake_case body; the SDK type wraps
// a camelCase app. Either may carry the one-time client secret.
interface RegisteredAppFields {
  clientId?: string;
  client_id?: string;
  clientSecret?: string;
  client_secret?: string;
}

interface RegisterAppAnswer extends RegisteredAppFields {
  app?: RegisteredAppFields;
}

interface RegisteredCredentials {
  clientId: string;
  clientSecret: string;
}

function credentialsFrom(data: unknown): RegisteredCredentials {
  const answer = (data ?? {}) as RegisterAppAnswer;
  return {
    clientId: answer.app?.clientId ?? answer.app?.client_id ?? answer.clientId ?? answer.client_id ?? '',
    clientSecret:
      answer.app?.clientSecret ?? answer.app?.client_secret ?? answer.clientSecret ?? answer.client_secret ?? '',
  };
}

export default function NewAppPage() {
  const router = useRouter();
  const { toast } = useToast();
  const iam = useIAM();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [grantTypes, setGrantTypes] = useState('client_credentials');
  const [registered, setRegistered] = useState<RegisteredCredentials | null>(null);

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
      onSuccess: (data) => {
        toast({ title: 'Application registered', variant: 'success' });
        setRegistered(credentialsFrom(data));
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
        {registered ? (
        <CardContent className="space-y-4">
          <Alert variant="warning">
            <AlertTitle>Save the client secret now</AlertTitle>
            <AlertDescription>
              The client secret is shown only once. Copy it before you leave this page; it cannot be
              shown again.
            </AlertDescription>
          </Alert>
          <div className="space-y-2">
            <Label>Client ID</Label>
            <code className="block rounded bg-muted px-2 py-1 font-mono text-sm break-all">
              {registered.clientId}
            </code>
          </div>
          <div className="space-y-2">
            <Label>Client Secret</Label>
            <code className="block rounded bg-muted px-2 py-1 font-mono text-sm break-all">
              {registered.clientSecret}
            </code>
          </div>
          <div className="flex gap-2 justify-end">
            <Button onClick={() => router.push('/iam/apps')}>Done</Button>
          </div>
        </CardContent>
        ) : (
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
            <Gated op="POST /api/v1/iam/tenants/{tenant}/apps">
              <Button
                onClick={() => createMutation.mutate(undefined)}
                disabled={!name || createMutation.isLoading}
              >
                {createMutation.isLoading && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Register Application
              </Button>
            </Gated>
          </div>
        </CardContent>
        )}
      </Card>
    </div>
  );
}

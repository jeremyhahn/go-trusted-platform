'use client';

/**
 * Create Profile from Template Page
 * Customize a device template to create a specific device profile
 */

import { useState } from 'react';
import { useRouter, useParams, usePathname } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  CheckCircle2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast, useApi, useDevice, useMutation } from '@/hooks';
import type { DeviceRole, CreateProfileFromTemplateRequest } from 'trusted-platform-sdk';
import { profileOverrides } from '@/lib/device-profile-networks';

// ============================================================================
// Helper Functions
// ============================================================================

function getRoleBadge(role: DeviceRole) {
  const roleLabels: Record<DeviceRole, string> = {
    UNSPECIFIED: 'Unspecified',
    UNKNOWN: 'Unknown',
    SERVER: 'Server',
    CLIENT: 'Client',
    WORKSTATION: 'Workstation',
    EDGE: 'Edge',
    IOT: 'IoT',
    GATEWAY: 'Gateway',
    LOAD_BALANCER: 'Load Balancer',
  };

  return <Badge variant="outline">{roleLabels[role] ?? role}</Badge>;
}

// ============================================================================
// Main Component
// ============================================================================

export default function CreateProfileClient() {
  const params = useParams<{ id: string }>();
  const pathname = usePathname();
  // Keep the template ID as a string; parseInt would truncate uint64
  // values above 2^53 and break the URL round trip.
  const templateId = resolveDynamicId(params, pathname, 'templates') as any;
  const router = useRouter();
  const { toast } = useToast();
  const deviceService = useDevice();

  const [hostname, setHostname] = useState('');
  const [staticIp, setStaticIp] = useState('');
  const [ekSerial, setEkSerial] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const [createdProfileId, setCreatedProfileId] = useState<number | null>(null);

  const {
    data: template,
    isLoading: templateLoading,
    error: templateError,
  } = useApi(
    () => deviceService.getTemplate(templateId),
    [templateId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading template',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const createProfileMutation = useMutation(
    async (request: CreateProfileFromTemplateRequest) => {
      return deviceService.createProfileFromTemplate(request);
    },
    {
      onSuccess: (profile) => {
        setCreatedProfileId(profile?.id ?? null);
        toast({
          title: 'Profile created',
          description: 'The device profile has been created from the template',
          variant: 'success',
        });
      },
      onError: (err) => {
        toast({
          title: 'Error creating profile',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    await createProfileMutation.mutateAsync({
      templateId,
      overrides: profileOverrides({ staticIp, ekSerial, macAddress }),
    });
  };

  if (templateLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground">Loading template...</p>
        </div>
      </div>
    );
  }

  if (templateError || !template) {
    return (
      <div className="flex flex-col gap-6">
        <Button
          variant="ghost"
          className="w-fit"
          onClick={() => router.push(`/devices/templates/${templateId}`)}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Template
        </Button>
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Template</AlertTitle>
          <AlertDescription>{templateError?.message ?? 'Template not found'}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (createdProfileId !== null) {
    return (
      <div className="flex flex-col gap-6">
        <Button
          variant="ghost"
          className="w-fit"
          onClick={() => router.push(`/devices/templates/${templateId}`)}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Template
        </Button>
        <Card className="max-w-lg mx-auto">
          <CardContent className="flex flex-col items-center gap-4 pt-8 pb-8">
            <CheckCircle2 className="h-16 w-16 text-green-500" />
            <h2 className="text-2xl font-bold">Profile Created</h2>
            <p className="text-muted-foreground text-center">
              A new device profile has been created from the &quot;{template.name}&quot; template.
            </p>
            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => router.push('/devices/profiles')}
              >
                View All Profiles
              </Button>
              <Button
                onClick={() => router.push(`/devices/profiles/${createdProfileId}`)}
              >
                View Profile
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 max-w-2xl">
      {/* Back navigation */}
      <Button
        variant="ghost"
        className="w-fit"
        onClick={() => router.push(`/devices/templates/${templateId}`)}
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Template
      </Button>

      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Create Profile from Template</h1>
        <p className="text-muted-foreground">
          Customize the template settings to create a device-specific profile
        </p>
      </div>

      {/* Template Summary */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Template</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div>
            <div className="font-medium">{template.name}</div>
            {template.description && (
              <div className="text-sm text-muted-foreground">{template.description}</div>
            )}
          </div>
          {getRoleBadge(template.role)}
        </CardContent>
      </Card>

      <Separator />

      {/* Customization Form */}
      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Device Identification</CardTitle>
            <CardDescription>
              Specify device identifiers to bind this profile to a specific physical device
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="ekSerial">EK Serial Number</Label>
              <Input
                id="ekSerial"
                value={ekSerial}
                onChange={(e) => setEkSerial(e.target.value)}
                placeholder="e.g., ABC123456789"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                TPM Endorsement Key serial number to bind this profile to a specific device
              </p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="macAddress">MAC Address</Label>
              <Input
                id="macAddress"
                value={macAddress}
                onChange={(e) => setMacAddress(e.target.value)}
                placeholder="e.g., 00:11:22:33:44:55"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Primary network interface MAC address to bind this profile to a specific device
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Network Customization</CardTitle>
            <CardDescription>
              Override network settings from the template for this specific device
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="hostname">Hostname</Label>
              <Input
                id="hostname"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="e.g., prod-server-01"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="staticIp">Static IP Address</Label>
              <Input
                id="staticIp"
                value={staticIp}
                onChange={(e) => setStaticIp(e.target.value)}
                placeholder="e.g., 192.168.1.100"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Leave blank to use the DHCP settings from the template
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end gap-3">
          <Button
            type="button"
            variant="outline"
            onClick={() => router.push(`/devices/templates/${templateId}`)}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={createProfileMutation.isLoading}>
            {createProfileMutation.isLoading && (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            )}
            Create Profile
          </Button>
        </div>
      </form>
    </div>
  );
}

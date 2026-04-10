'use client';

/**
 * Provisioning Session Detail Page
 * QR code landing page for operators to assign a profile to a device
 *
 * This page is accessed when an operator scans the QR code displayed on a
 * device's initial boot screen. The operator can assign a template to
 * create a profile or create a fully custom profile directly.
 */

import { useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  ArrowLeft,
  AlertCircle,
  Loader2,
  CheckCircle2,
  Cpu,
  Network,
  Clock,
  XCircle,
  LayoutTemplate,
  Plus,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast, useApi, useDevice, useMutation, useDeviceTemplates } from '@/hooks';
import type {
  DeviceRole,
  CreateProfileFromTemplateRequest,
  CreateProfileRequest,
} from 'trusted-platform-sdk';

// ============================================================================
// Helper Functions
// ============================================================================

type SessionStatus = 'pending' | 'fulfilled' | 'expired';

function getSessionStatus(fulfilled: boolean, expiresAt: string): SessionStatus {
  if (fulfilled) return 'fulfilled';
  if (new Date(expiresAt) < new Date()) return 'expired';
  return 'pending';
}

function getStatusBadge(status: SessionStatus) {
  switch (status) {
    case 'pending':
      return (
        <Badge variant="outline" className="border-yellow-500 text-yellow-600 dark:text-yellow-400">
          <Clock className="mr-1 h-3 w-3" />
          Pending
        </Badge>
      );
    case 'fulfilled':
      return (
        <Badge variant="outline" className="border-green-500 text-green-600 dark:text-green-400">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          Fulfilled
        </Badge>
      );
    case 'expired':
      return (
        <Badge variant="outline" className="border-red-500 text-red-600 dark:text-red-400">
          <XCircle className="mr-1 h-3 w-3" />
          Expired
        </Badge>
      );
  }
}

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ============================================================================
// Main Component
// ============================================================================

export default function SessionDetailClient() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params.sessionId;
  const router = useRouter();
  const { toast } = useToast();
  const deviceService = useDevice();

  const [activeTab, setActiveTab] = useState<'template' | 'custom'>('template');
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [isFulfilled, setIsFulfilled] = useState(false);
  const [createdProfileId, setCreatedProfileId] = useState<number | null>(null);

  // Template form state
  const [templateEkSerial, setTemplateEkSerial] = useState('');
  const [templateMacAddress, setTemplateMacAddress] = useState('');
  const [templateStaticIp, setTemplateStaticIp] = useState('');

  // Custom profile form state
  const [profileName, setProfileName] = useState('');
  const [profileRole, setProfileRole] = useState<DeviceRole>('SERVER');
  const [profileEkSerial, setProfileEkSerial] = useState('');
  const [profileMacAddress, setProfileMacAddress] = useState('');

  const { templates, isLoading: templatesLoading } = useDeviceTemplates();

  const {
    data: session,
    isLoading: sessionLoading,
    error: sessionError,
    refetch,
  } = useApi(
    () => deviceService.getProvisioningSession(sessionId),
    [sessionId],
    {
      onSuccess: (data) => {
        if (data) {
          setTemplateEkSerial(data.ekSerial ?? '');
          setTemplateMacAddress(data.macAddress ?? '');
          setProfileEkSerial(data.ekSerial ?? '');
          setProfileMacAddress(data.macAddress ?? '');
          if (data.fulfilled) {
            setIsFulfilled(true);
          }
        }
      },
      onError: (err) => {
        toast({
          title: 'Error loading session',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Mutation: create profile from template AND fulfill the session atomically
  const createFromTemplateMutation = useMutation(
    async (request: CreateProfileFromTemplateRequest) => {
      const profileResponse = await deviceService.createProfileFromTemplate(request);
      const profile = profileResponse.data;
      if (profile?.id) {
        await deviceService.fulfillProvisioningSession({
          sessionId,
          profileId: profile.id,
        });
      }
      return profileResponse;
    },
    {
      onSuccess: (profileResponse) => {
        const profileId = profileResponse?.id ?? null;
        setCreatedProfileId(profileId);
        setIsFulfilled(true);
        toast({
          title: 'Device provisioned',
          description: 'Profile created and session fulfilled. The device will resume installation.',
          variant: 'success',
        });
      },
      onError: (err) => {
        toast({
          title: 'Error provisioning device',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Mutation: create custom profile AND fulfill the session atomically
  const createCustomProfileMutation = useMutation(
    async (request: CreateProfileRequest) => {
      const profileResponse = await deviceService.createProfile(request);
      const profile = profileResponse.data?.profile;
      if (profile?.id) {
        await deviceService.fulfillProvisioningSession({
          sessionId,
          profileId: profile.id,
        });
      }
      return profileResponse;
    },
    {
      onSuccess: (profileResponse) => {
        const profileId = profileResponse?.profile?.id ?? null;
        setCreatedProfileId(profileId);
        setIsFulfilled(true);
        toast({
          title: 'Device provisioned',
          description: 'Profile created and session fulfilled. The device will resume installation.',
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

  const handleCreateFromTemplate = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedTemplateId) {
      toast({
        title: 'No template selected',
        description: 'Please select a template to continue',
        variant: 'destructive',
      });
      return;
    }

    createFromTemplateMutation.mutate({
      templateId: parseInt(selectedTemplateId, 10),
      ekSerial: templateEkSerial || undefined,
      macAddress: templateMacAddress || undefined,
      overrides: templateStaticIp
        ? { productionNetwork: { staticIp: templateStaticIp } }
        : undefined,
    });
  };

  const handleCreateCustomProfile = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    createCustomProfileMutation.mutate({
      profile: {
        name: profileName,
        role: profileRole,
        ekSerial: profileEkSerial || undefined,
        macAddress: profileMacAddress || undefined,
      },
    });
  };

  if (sessionLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground">Loading session...</p>
        </div>
      </div>
    );
  }

  if (sessionError || !session) {
    return (
      <div className="flex flex-col gap-6">
        <Button
          variant="ghost"
          className="w-fit"
          onClick={() => router.push('/provisioning/sessions')}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Sessions
        </Button>
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Session Not Found</AlertTitle>
          <AlertDescription>
            {sessionError?.message ?? 'This provisioning session could not be found or has expired.'}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  const status = getSessionStatus(session.fulfilled, session.expiresAt);

  // Success state after provisioning
  if (isFulfilled && !session.fulfilled) {
    refetch();
  }

  if (isFulfilled) {
    return (
      <div className="flex flex-col gap-6 max-w-lg mx-auto">
        <Button
          variant="ghost"
          className="w-fit"
          onClick={() => router.push('/provisioning/sessions')}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Sessions
        </Button>
        <Card>
          <CardContent className="flex flex-col items-center gap-4 pt-8 pb-8 text-center">
            <CheckCircle2 className="h-16 w-16 text-green-500" />
            <h2 className="text-2xl font-bold">Device Provisioned</h2>
            <p className="text-muted-foreground">
              The device profile has been created and the provisioning session has been
              fulfilled. The device will automatically resume its installation process.
            </p>
            <div className="flex gap-3 flex-wrap justify-center">
              <Button variant="outline" onClick={() => router.push('/provisioning/sessions')}>
                View All Sessions
              </Button>
              {createdProfileId && (
                <Button onClick={() => router.push(`/devices/profiles/${createdProfileId}`)}>
                  View Profile
                </Button>
              )}
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
        onClick={() => router.push('/provisioning/sessions')}
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Sessions
      </Button>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Provisioning Session</h1>
          <p className="text-muted-foreground font-mono text-sm mt-1">{sessionId}</p>
        </div>
        {getStatusBadge(status)}
      </div>

      {/* Session Info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Device Information</CardTitle>
          <CardDescription>Reported by the device during boot</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <Cpu className="h-4 w-4" />
              EK Serial
            </span>
            <span className="font-mono text-sm">{session.ekSerial || 'Not reported'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <Network className="h-4 w-4" />
              MAC Address
            </span>
            <span className="font-mono text-sm">{session.macAddress || 'Not reported'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="h-4 w-4" />
              Created
            </span>
            <span className="text-sm">{formatDate(session.createdAt)}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="h-4 w-4" />
              Expires
            </span>
            <span className="text-sm">{formatDate(session.expiresAt)}</span>
          </div>
        </CardContent>
      </Card>

      {status === 'expired' && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Session Expired</AlertTitle>
          <AlertDescription>
            This provisioning session has expired and can no longer be fulfilled.
            The device will need to restart its provisioning process.
          </AlertDescription>
        </Alert>
      )}

      {status === 'pending' && (
        <>
          <Separator />

          {/* Provisioning Options */}
          <div>
            <h2 className="text-lg font-semibold mb-1">Assign a Profile</h2>
            <p className="text-sm text-muted-foreground">
              Choose how to provision this device. Once a profile is assigned, the device
              will automatically continue its installation.
            </p>
          </div>

          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'template' | 'custom')}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="template" className="flex items-center gap-2">
                <LayoutTemplate className="h-4 w-4" />
                From Template
              </TabsTrigger>
              <TabsTrigger value="custom" className="flex items-center gap-2">
                <Plus className="h-4 w-4" />
                Custom Profile
              </TabsTrigger>
            </TabsList>

            {/* Template Option */}
            <TabsContent value="template">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Create Profile from Template</CardTitle>
                  <CardDescription>
                    Select a predefined template and optionally customize device-specific settings
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleCreateFromTemplate} className="grid gap-4">
                    <div className="grid gap-2">
                      <Label>Template</Label>
                      {templatesLoading ? (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Loading templates...
                        </div>
                      ) : templates.length === 0 ? (
                        <Alert>
                          <AlertCircle className="h-4 w-4" />
                          <AlertDescription>
                            No templates available.{' '}
                            <Button
                              variant="link"
                              className="h-auto p-0"
                              onClick={() => router.push('/devices/templates')}
                            >
                              Create a template first
                            </Button>
                          </AlertDescription>
                        </Alert>
                      ) : (
                        <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                          <SelectTrigger>
                            <SelectValue placeholder="Choose a device template..." />
                          </SelectTrigger>
                          <SelectContent>
                            {templates.map((t) => (
                              <SelectItem key={t.id} value={String(t.id)}>
                                {t.name} — {t.role}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      )}
                    </div>

                    <Separator />
                    <p className="text-sm font-medium">Device-Specific Overrides (optional)</p>

                    <div className="grid gap-2">
                      <Label htmlFor="t-ekserial">EK Serial</Label>
                      <Input
                        id="t-ekserial"
                        value={templateEkSerial}
                        onChange={(e) => setTemplateEkSerial(e.target.value)}
                        placeholder="TPM EK serial number"
                        className="font-mono"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="t-mac">MAC Address</Label>
                      <Input
                        id="t-mac"
                        value={templateMacAddress}
                        onChange={(e) => setTemplateMacAddress(e.target.value)}
                        placeholder="00:11:22:33:44:55"
                        className="font-mono"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="t-staticip">Static IP (optional)</Label>
                      <Input
                        id="t-staticip"
                        value={templateStaticIp}
                        onChange={(e) => setTemplateStaticIp(e.target.value)}
                        placeholder="Leave blank to use DHCP from template"
                        className="font-mono"
                      />
                    </div>

                    <Button
                      type="submit"
                      className="w-full"
                      disabled={
                        !selectedTemplateId ||
                        createFromTemplateMutation.isLoading ||
                        templatesLoading
                      }
                    >
                      {createFromTemplateMutation.isLoading && (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      )}
                      Create Profile and Provision Device
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Custom Profile Option */}
            <TabsContent value="custom">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Create Custom Profile</CardTitle>
                  <CardDescription>
                    Define a completely custom profile for this device
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleCreateCustomProfile} className="grid gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="p-name">Profile Name</Label>
                      <Input
                        id="p-name"
                        value={profileName}
                        onChange={(e) => setProfileName(e.target.value)}
                        placeholder="e.g., prod-server-01"
                        required
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="p-role">Device Role</Label>
                      <Select
                        value={profileRole}
                        onValueChange={(v) => setProfileRole(v as DeviceRole)}
                      >
                        <SelectTrigger id="p-role">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="SERVER">Server</SelectItem>
                          <SelectItem value="CLIENT">Client</SelectItem>
                          <SelectItem value="WORKSTATION">Workstation</SelectItem>
                          <SelectItem value="EDGE">Edge</SelectItem>
                          <SelectItem value="IOT">IoT</SelectItem>
                          <SelectItem value="GATEWAY">Gateway</SelectItem>
                          <SelectItem value="LOAD_BALANCER">Load Balancer</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="p-ekserial">EK Serial</Label>
                      <Input
                        id="p-ekserial"
                        value={profileEkSerial}
                        onChange={(e) => setProfileEkSerial(e.target.value)}
                        placeholder="TPM EK serial number"
                        className="font-mono"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="p-mac">MAC Address</Label>
                      <Input
                        id="p-mac"
                        value={profileMacAddress}
                        onChange={(e) => setProfileMacAddress(e.target.value)}
                        placeholder="00:11:22:33:44:55"
                        className="font-mono"
                      />
                    </div>

                    <Button
                      type="submit"
                      className="w-full"
                      disabled={!profileName || createCustomProfileMutation.isLoading}
                    >
                      {createCustomProfileMutation.isLoading && (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      )}
                      Create Profile and Provision Device
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}

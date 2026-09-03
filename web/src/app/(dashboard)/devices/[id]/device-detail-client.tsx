'use client';

/**
 * Device Detail Page
 * Display detailed information about a specific device
 */

import { useState, useEffect } from 'react';
import { deriveDeviceStatus } from '@/lib/device-status';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { ArrowLeft, Shield, FileText, Key, Trash2, Power, BanIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DeviceCard } from '@/components/features/devices/device-card';
import { TPMInfo } from '@/components/features/devices/tpm-info';
import { useToast } from '@/hooks/use-toast';
import { useDevice, useMutation } from '@/hooks';
import { ATTESTATION_UNAVAILABLE } from '@/lib/attestation';
import type { DeviceDetail, AttestationRecord, DeviceCertificate } from '@/types/device';

export default function DeviceDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const deviceService = useDevice();
  const deviceId = resolveDynamicId(params, pathname, 'devices');

  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchDevice = async () => {
    setIsLoading(true);
    try {
      const response = await deviceService.getDevice(deviceId as any);

      if (response.data) {
        setDevice(normalizeDevice(response.data));
      } else {
        throw new Error('Failed to fetch device');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to fetch device',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  // normalizeDevice reshapes the raw SDK/REST device payload into the
  // DeviceDetail shape this page expects. The REST API returns
  // snake_case fields (`attest_pub`, `ek_cert`, `created_at`) and the
  // SDK does not yet transform them, so we have to accept both forms.
  // The list page does the same transform — keep them in sync.
  function normalizeDevice(raw: any): DeviceDetail {
    const attestPub = raw.attestPub || raw.attest_pub;
    const ekCert = raw.ekCert || raw.ek_cert;
    const eventLog = raw.eventLog || raw.event_log;
    const signingPub = raw.signingPub || raw.signing_pub;
    const createdAt = raw.createdAt || raw.created_at;
    const updatedAt = raw.updatedAt || raw.updated_at;
    const lastHeartbeatAt = raw.lastHeartbeatAt || raw.last_heartbeat_at;
    const lifecycleState: string = raw.state || '';
    const serial: string | undefined = raw.serial || undefined;
    const model: string | undefined = raw.model || undefined;
    return {
      id: String(raw.id),
      // Use the hostname-derived serial as the user-visible name. Falls
      // back to model only when no serial was supplied (manual UI
      // registration where serial is optional).
      name: serial || model || 'Unknown',
      // Devices enrolled via ACME enroll-01 are hardware nodes with a
      // real TPM. The Device entity doesn't yet carry a separate
      // physical/virtual type flag, so default to physical to match
      // the list-page transformer.
      type: 'physical',
      model,
      serial,
      // Enforcement states always win; otherwise the badge derives from
      // heartbeat freshness with the same five-minute threshold as the
      // list page: never-seen → unknown, fresh → online, stale → offline.
      status: deriveDeviceStatus(lifecycleState, lastHeartbeatAt),
      // Liveness is the node's last mTLS heartbeat, never updated_at.
      lastSeen: lastHeartbeatAt || undefined,
      registeredAt: createdAt || new Date().toISOString(),
      tpm: attestPub ? {
        manufacturer: model || 'Unknown',
        version: '2.0',
        firmwareVersion: '1.0',
        hasEK: !!ekCert,
        hasSRK: false,
      } : undefined,
      endorsementKey: ekCert ? {
        id: `${raw.id}-ek`,
        keyType: 'RSA',
        publicKey: ekCert,
        createdAt: createdAt || new Date().toISOString(),
      } : undefined,
      // Attestation history + per-device certificate list are populated
      // by separate endpoints (not yet wired into the WebUI), so leave
      // empty rather than dropping invented rows in.
      attestationHistory: [],
      certificates: [],
      // Carry through the raw enrollment blobs in case downstream
      // components need them. Cast as any to widen DeviceDetail without
      // touching its declared shape; the local type is permissive enough
      // because the page already passes `device as any` in places.
      ...(eventLog ? { eventLog } : {}),
      ...(signingPub ? { signingPub } : {}),
    } as DeviceDetail;
  }

  useEffect(() => {
    if (deviceId) {
      fetchDevice();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId]);

  // Per-device attestation is not wired to anything real yet. This used to
  // call collectHostAttestation(), which attests THIS control plane's own
  // TPM and then reported "Attestation completed successfully" for the
  // device being viewed — a green result for a machine that was never
  // attested. Disabled until the attestation reporting service lands (#226).

  const updateMutation = useMutation(
    async (data: Record<string, unknown>) => {
      if (!device) {
        throw new Error('Device not loaded');
      }
      // Map DeviceDetail to SDK Device type
      const sdkDevice = {
        id: device.id as any,
        serial: device.serial || '',
        hashAlgoId: 0, // Default value
        createdAt: device.registeredAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...data
      };
      return await deviceService.updateDevice({
        device: sdkDevice as any
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Device updated successfully',
        });
        fetchDevice();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to update device',
          variant: 'destructive',
        });
      },
    }
  );

  const deleteMutation = useMutation(
    async (_: void) => {
      return await deviceService.deleteDevice(deviceId as any);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Device deleted successfully',
        });
        router.push('/devices');
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to delete device',
          variant: 'destructive',
        });
      },
    }
  );

  const handleToggleStatus = async () => {
    if (!device) return;
    // Note: Device type from SDK doesn't have an enabled field
    // This is a placeholder - actual implementation depends on backend API
    toast({
      title: 'Info',
      description: 'Device status toggle not yet implemented in SDK',
      variant: 'default',
    });
  };

  const handleDelete = async () => {
    if (!device) return;

    if (!confirm(`Are you sure you want to delete ${device.name}? This action cannot be undone.`)) {
      return;
    }

    deleteMutation.mutate(undefined);
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getAttestationStatusBadge = (status: AttestationRecord['status']) => {
    const variants: Record<AttestationRecord['status'], { variant: 'default' | 'secondary' | 'destructive'; label: string }> = {
      passed: { variant: 'default', label: 'Passed' },
      failed: { variant: 'destructive', label: 'Failed' },
      pending: { variant: 'secondary', label: 'Pending' },
    };

    const { variant, label } = variants[status];
    return <Badge variant={variant}>{label}</Badge>;
  };

  const getCertificateStatusBadge = (status: DeviceCertificate['status']) => {
    const variants: Record<DeviceCertificate['status'], { variant: 'default' | 'secondary' | 'destructive'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      revoked: { variant: 'destructive', label: 'Revoked' },
      expired: { variant: 'secondary', label: 'Expired' },
    };

    const { variant, label } = variants[status];
    return <Badge variant={variant}>{label}</Badge>;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent motion-reduce:animate-[spin_1.5s_linear_infinite]" />
          <p className="mt-2 text-sm text-muted-foreground">Loading device details...</p>
        </div>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg font-medium">Device not found</p>
        <Button className="mt-4" onClick={() => router.push('/devices')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Devices
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{device.name}</h1>
            <p className="text-muted-foreground">Device details and management</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {device.tpm && (
            <Button disabled title={ATTESTATION_UNAVAILABLE}>
              <Shield className="mr-2 h-4 w-4" />
              Run Attestation (unavailable)
            </Button>
          )}
          <Button
            variant="outline"
            onClick={handleToggleStatus}
          >
            {device.status === 'disabled' ? (
              <>
                <Power className="mr-2 h-4 w-4" />
                Enable
              </>
            ) : (
              <>
                <BanIcon className="mr-2 h-4 w-4" />
                Disable
              </>
            )}
          </Button>
          <Button variant="destructive" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <DeviceCard device={device} />
        <TPMInfo tpm={device.tpm} />
      </div>

      {device.endorsementKey && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Endorsement Key
            </CardTitle>
            <CardDescription>
              TPM endorsement key information
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Key Type</dt>
                <dd className="mt-1">
                  <Badge variant="outline">{device.endorsementKey.keyType}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Created</dt>
                <dd className="mt-1 text-sm">{formatDate(device.endorsementKey.createdAt)}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-sm font-medium text-muted-foreground">Public Key</dt>
                <dd className="mt-1">
                  <code className="block rounded bg-muted p-2 text-xs font-mono break-all">
                    {device.endorsementKey.publicKey}
                  </code>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="attestations" className="space-y-4">
        <TabsList>
          <TabsTrigger value="attestations">
            <Shield className="mr-2 h-4 w-4" />
            Attestation History
          </TabsTrigger>
          <TabsTrigger value="certificates">
            <FileText className="mr-2 h-4 w-4" />
            Certificates
          </TabsTrigger>
        </TabsList>

        <TabsContent value="attestations">
          <Card>
            <CardHeader>
              <CardTitle>Attestation History</CardTitle>
              <CardDescription>
                Recent attestation records for this device
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>PCR Count</TableHead>
                      <TableHead className="text-right">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(device.attestationHistory || []).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="text-center text-muted-foreground">
                          No attestation records found
                        </TableCell>
                      </TableRow>
                    ) : (
                      (device.attestationHistory || []).map((record) => (
                        <TableRow key={record.id}>
                          <TableCell className="text-sm">
                            {formatDate(record.timestamp)}
                          </TableCell>
                          <TableCell>
                            {getAttestationStatusBadge(record.status)}
                          </TableCell>
                          <TableCell>
                            {Object.keys(record.pcrValues).length} PCRs
                          </TableCell>
                          <TableCell className="text-right">
                            <Button variant="ghost" size="sm">
                              View Details
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="certificates">
          <Card>
            <CardHeader>
              <CardTitle>Device Certificates</CardTitle>
              <CardDescription>
                Certificates associated with this device
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Subject</TableHead>
                      <TableHead>Serial Number</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Expires</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(device.certificates || []).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground">
                          No certificates found
                        </TableCell>
                      </TableRow>
                    ) : (
                      (device.certificates || []).map((cert) => (
                        <TableRow key={cert.id}>
                          <TableCell>
                            <Badge variant="outline">{cert.type}</Badge>
                          </TableCell>
                          <TableCell className="text-sm">{cert.subject}</TableCell>
                          <TableCell>
                            <code className="text-xs font-mono">{cert.serialNumber}</code>
                          </TableCell>
                          <TableCell>
                            {getCertificateStatusBadge(cert.status)}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {formatDate(cert.expiresAt)}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

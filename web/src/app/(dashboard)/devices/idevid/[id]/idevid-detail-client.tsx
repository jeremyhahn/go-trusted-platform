'use client';

/**
 * IDevID Detail Page
 * Display detailed information about a specific IDevID certificate
 */

import { useState, useEffect } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  FileText,
  RefreshCw,
  XCircle,
  Download,
  CheckCircle,
  AlertCircle,
  Link as LinkIcon,
  Key,
  Shield,
} from 'lucide-react';
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
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { useIDevID, useMutation } from '@/hooks';
import type { IDevIDDetail } from '@/types/device';

export default function IDevIDDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const idevidService = useIDevID();
  const idevIdId = resolveDynamicId(params, pathname, 'idevid');

  const [idevid, setIDevID] = useState<IDevIDDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    valid: boolean;
    errors?: string[];
  } | null>(null);

  const fetchIDevID = async () => {
    setIsLoading(true);
    try {
      const response = await idevidService.getIDevIDInfo();

      if (response.data) {
        // Map SDK response to detail format
        // The REST payload carries the IDevIDDetail fields, which differ
        // from the SDK/proto declaration (#445).
        setIDevID(response.data as unknown as IDevIDDetail);
      } else {
        throw new Error('Failed to fetch certificate');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to fetch certificate',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (idevIdId) {
      fetchIDevID();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idevIdId]);

  const renewMutation = useMutation(
    async (_: void) => {
      const deleteResponse = await idevidService.deleteIDevID();
      if (!deleteResponse.data?.status.success) {
        throw new Error(deleteResponse.data?.status.message || 'Failed to delete IDevID');
      }
      return await idevidService.generateIDevID();
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Certificate renewed successfully',
        });
        fetchIDevID();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to renew certificate',
          variant: 'destructive',
        });
      },
    }
  );

  const revokeMutation = useMutation(
    async (_: void) => {
      return await idevidService.deleteIDevIDCertificate();
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Certificate revoked successfully',
        });
        fetchIDevID();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to revoke certificate',
          variant: 'destructive',
        });
      },
    }
  );

  const handleRenew = async () => {
    if (!idevid) return;
    renewMutation.mutate(undefined);
  };

  const handleRevoke = async () => {
    if (!idevid) return;

    if (!confirm(`Are you sure you want to revoke the certificate for ${idevid.deviceName}? This action cannot be undone.`)) {
      return;
    }

    revokeMutation.mutate(undefined);
  };

  const handleDownload = async () => {
    if (!idevid) return;

    try {
      const response = await idevidService.getIDevIDCertificate();

      if (response.data?.certificate?.pem) {
        // DeviceIdentityCertificate has a pem property that contains the PEM string
        const blob = new Blob([response.data.certificate.pem], { type: 'application/x-pem-file' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${idevid.deviceName}-idevid.pem`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        toast({
          title: 'Success',
          description: 'Certificate downloaded successfully',
        });
      } else {
        throw new Error('Certificate PEM not available');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to download certificate',
        variant: 'destructive',
      });
    }
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      // Note: SDK doesn't have certificate chain verification, using placeholder
      toast({
        title: 'Info',
        description: 'Certificate verification not yet implemented in SDK',
        variant: 'default',
      });
    } finally {
      setIsVerifying(false);
    }
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

  const getStatusBadge = (status: IDevIDDetail['status']) => {
    const variants: Record<IDevIDDetail['status'], { variant: 'default' | 'secondary' | 'destructive' | 'outline'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      revoked: { variant: 'destructive', label: 'Revoked' },
      expired: { variant: 'secondary', label: 'Expired' },
      pending: { variant: 'outline', label: 'Pending' },
    };

    const { variant, label } = variants[status];
    return <Badge variant={variant}>{label}</Badge>;
  };

  const isExpiringSoon = (expiresAt: string): boolean => {
    const expiryDate = new Date(expiresAt);
    const now = new Date();
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return daysUntilExpiry <= 30 && daysUntilExpiry > 0;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent motion-reduce:animate-[spin_1.5s_linear_infinite]" />
          <p className="mt-2 text-sm text-muted-foreground">Loading certificate details...</p>
        </div>
      </div>
    );
  }

  if (!idevid) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg font-medium">Certificate not found</p>
        <Button className="mt-4" onClick={() => router.push('/devices/idevid')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Certificates
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
            <h1 className="text-3xl font-bold tracking-tight">{idevid.deviceName}</h1>
            <p className="text-muted-foreground">IDevID certificate details</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={handleDownload}>
            <Download className="mr-2 h-4 w-4" />
            Download
          </Button>
          {idevid.status === 'active' && (
            <>
              <Button variant="outline" onClick={handleRenew}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Renew
              </Button>
              <Button variant="destructive" onClick={handleRevoke}>
                <XCircle className="mr-2 h-4 w-4" />
                Revoke
              </Button>
            </>
          )}
        </div>
      </div>

      {isExpiringSoon(idevid.expiresAt) && idevid.status === 'active' && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Certificate Expiring Soon</AlertTitle>
          <AlertDescription>
            This certificate will expire on {formatDate(idevid.expiresAt)}.
            Consider renewing it to avoid service interruption.
          </AlertDescription>
        </Alert>
      )}

      {verificationResult && (
        <Alert variant={verificationResult.valid ? 'default' : 'destructive'}>
          {verificationResult.valid ? (
            <>
              <CheckCircle className="h-4 w-4" />
              <AlertTitle>Certificate Chain Valid</AlertTitle>
              <AlertDescription>
                The certificate chain has been successfully verified.
              </AlertDescription>
            </>
          ) : (
            <>
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Certificate Chain Invalid</AlertTitle>
              <AlertDescription>
                {verificationResult.errors && verificationResult.errors.length > 0 ? (
                  <ul className="mt-2 list-inside list-disc">
                    {verificationResult.errors.map((error, index) => (
                      <li key={index}>{error}</li>
                    ))}
                  </ul>
                ) : (
                  'Certificate chain validation failed.'
                )}
              </AlertDescription>
            </>
          )}
        </Alert>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Certificate Information
              </CardTitle>
              <CardDescription>Basic certificate details</CardDescription>
            </div>
            <Button variant="outline" onClick={handleVerify} disabled={isVerifying}>
              <Shield className="mr-2 h-4 w-4" />
              {isVerifying ? 'Verifying...' : 'Verify Chain'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Device</dt>
              <dd className="mt-1 text-sm font-medium">{idevid.deviceName}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Status</dt>
              <dd className="mt-1">{getStatusBadge(idevid.status)}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-sm font-medium text-muted-foreground">Subject</dt>
              <dd className="mt-1 text-sm font-mono">{idevid.subject}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Serial Number</dt>
              <dd className="mt-1">
                <code className="text-xs font-mono">{idevid.serialNumber}</code>
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Signature Algorithm</dt>
              <dd className="mt-1 text-sm">{idevid.signatureAlgorithm}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Issued</dt>
              <dd className="mt-1 text-sm">{formatDate(idevid.issuedAt)}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Expires</dt>
              <dd className="mt-1 text-sm">{formatDate(idevid.expiresAt)}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Key Information
          </CardTitle>
          <CardDescription>Public key details</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Algorithm</dt>
              <dd className="mt-1">
                <Badge variant="outline">{idevid.keyAlgorithm}</Badge>
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Key Size</dt>
              <dd className="mt-1 text-sm">{idevid.keySize} bits</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-sm font-medium text-muted-foreground">Public Key</dt>
              <dd className="mt-1">
                <code className="block rounded bg-muted p-2 text-xs font-mono break-all">
                  {idevid.publicKey}
                </code>
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Tabs defaultValue="chain" className="space-y-4">
        <TabsList>
          <TabsTrigger value="chain">
            <LinkIcon className="mr-2 h-4 w-4" />
            Certificate Chain
          </TabsTrigger>
          <TabsTrigger value="extensions">
            <FileText className="mr-2 h-4 w-4" />
            Extensions
          </TabsTrigger>
          <TabsTrigger value="renewals">
            <RefreshCw className="mr-2 h-4 w-4" />
            Renewal History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="chain">
          <Card>
            <CardHeader>
              <CardTitle>Certificate Chain</CardTitle>
              <CardDescription>
                Full certificate chain from device to root CA
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="text-sm font-medium mb-2">Device Certificate</h4>
                <code className="block rounded bg-muted p-4 text-xs font-mono break-all max-h-40 overflow-y-auto">
                  {idevid.chain.certificate}
                </code>
              </div>
              {idevid.chain.intermediate.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2">Intermediate Certificates</h4>
                  <div className="space-y-2">
                    {idevid.chain.intermediate.map((cert, index) => (
                      <code
                        key={index}
                        className="block rounded bg-muted p-4 text-xs font-mono break-all max-h-40 overflow-y-auto"
                      >
                        {cert}
                      </code>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <h4 className="text-sm font-medium mb-2">Root CA Certificate</h4>
                <code className="block rounded bg-muted p-4 text-xs font-mono break-all max-h-40 overflow-y-auto">
                  {idevid.chain.root}
                </code>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="extensions">
          <Card>
            <CardHeader>
              <CardTitle>Certificate Extensions</CardTitle>
              <CardDescription>
                X.509 extensions included in this certificate
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Extension</TableHead>
                      <TableHead>Value</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.keys(idevid.extensions).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={2} className="text-center text-muted-foreground">
                          No extensions found
                        </TableCell>
                      </TableRow>
                    ) : (
                      Object.entries(idevid.extensions).map(([key, value]) => (
                        <TableRow key={key}>
                          <TableCell className="font-medium">{key}</TableCell>
                          <TableCell className="font-mono text-sm">{value}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="renewals">
          <Card>
            <CardHeader>
              <CardTitle>Renewal History</CardTitle>
              <CardDescription>
                Previous renewals of this certificate
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Renewed At</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Previous Certificate</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {idevid.renewals.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} className="text-center text-muted-foreground">
                          No renewal history
                        </TableCell>
                      </TableRow>
                    ) : (
                      idevid.renewals.map((renewal) => (
                        <TableRow key={renewal.id}>
                          <TableCell className="text-sm">
                            {formatDate(renewal.renewedAt)}
                          </TableCell>
                          <TableCell className="text-sm">{renewal.reason}</TableCell>
                          <TableCell>
                            <code className="text-xs font-mono">{renewal.previousCertId}</code>
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

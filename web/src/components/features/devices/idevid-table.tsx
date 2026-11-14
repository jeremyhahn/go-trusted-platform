'use client';

/**
 * IDevIDTable Component
 * DataTable for displaying and managing IDevID certificates
 */

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  MoreHorizontal,
  Eye,
  RefreshCw,
  XCircle,
  Download,
  AlertCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { useIDevID, useMutation } from '@/hooks';
import type { IDevID } from '@/types/device';

interface IDevIDTableProps {
  idevids: IDevID[];
  onIDevIDChange?: () => void;
}

export function IDevIDTable({ idevids, onIDevIDChange }: IDevIDTableProps) {
  const router = useRouter();
  const { toast } = useToast();
  const idevid = useIDevID();
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const renewMutation = useMutation(
    async (deviceName: string) => {
      // Renew by regenerating IDevID
      const deleteResponse = await idevid.deleteIDevID();
      if (deleteResponse.error) {
        throw new Error(deleteResponse.error.message || 'Failed to delete IDevID');
      }
      const generateResponse = await idevid.generateIDevID({});
      if (generateResponse.error) {
        throw new Error(generateResponse.error.message || 'Failed to generate IDevID');
      }
      return generateResponse;
    },
    {
      onSuccess: (data, deviceName) => {
        toast({
          title: 'Success',
          description: `IDevID certificate for ${deviceName} renewed`,
        });
        onIDevIDChange?.();
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
    async () => {
      const response = await idevid.deleteIDevIDCertificate();
      if (response.error) {
        throw new Error(response.error.message || 'Failed to revoke certificate');
      }
      return response;
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Certificate revoked successfully',
        });
        onIDevIDChange?.();
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

  const handleRenew = async (cert: IDevID) => {
    setLoadingId(cert.id);
    try {
      await renewMutation.mutateAsync(cert.deviceName);
    } catch {
      // onError has already shown the refusal.
    } finally {
      setLoadingId(null);
    }
  };

  const handleRevoke = async (cert: IDevID) => {
    if (!confirm(`Are you sure you want to revoke the certificate for ${cert.deviceName}? This action cannot be undone.`)) {
      return;
    }

    setLoadingId(cert.id);
    try {
      await revokeMutation.mutateAsync(undefined);
    } catch {
      // onError has already shown the refusal.
    } finally {
      setLoadingId(null);
    }
  };

  const handleDownload = async (cert: IDevID) => {
    setLoadingId(cert.id);
    try {
      const response = await idevid.getIDevIDCertificate();

      if (response.error) {
        toast({
          title: 'Error',
          description: response.error.message || 'Failed to download certificate',
          variant: 'destructive',
        });
        return;
      }

      if (response.data?.certificate?.pem) {
        const blob = new Blob([response.data.certificate.pem], { type: 'application/x-pem-file' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${cert.deviceName}-idevid.pem`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        toast({
          title: 'Success',
          description: 'Certificate downloaded successfully',
        });
      } else {
        toast({
          title: 'Error',
          description: 'Failed to download certificate: No certificate data',
          variant: 'destructive',
        });
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to download certificate',
        variant: 'destructive',
      });
    } finally {
      setLoadingId(null);
    }
  };

  const getStatusBadge = (status: IDevID['status']) => {
    const variants: Record<IDevID['status'], { variant: 'default' | 'secondary' | 'destructive' | 'outline'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      revoked: { variant: 'destructive', label: 'Revoked' },
      expired: { variant: 'secondary', label: 'Expired' },
      pending: { variant: 'outline', label: 'Pending' },
    };

    const { variant, label } = variants[status];
    return <Badge variant={variant}>{label}</Badge>;
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  const isExpiringSoon = (expiresAt: string): boolean => {
    const expiryDate = new Date(expiresAt);
    const now = new Date();
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    return daysUntilExpiry <= 30 && daysUntilExpiry > 0;
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Device</TableHead>
            <TableHead>Subject</TableHead>
            <TableHead>Serial Number</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Issued</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {idevids.length === 0 ? (
            <TableRow>
              <TableCell colSpan={7} className="text-center text-muted-foreground">
                No IDevID certificates found
              </TableCell>
            </TableRow>
          ) : (
            idevids.map((idevid) => (
              <TableRow key={idevid.id}>
                <TableCell className="font-medium">{idevid.deviceName}</TableCell>
                <TableCell className="text-sm">{idevid.subject}</TableCell>
                <TableCell>
                  <code className="text-xs font-mono">{idevid.serialNumber}</code>
                </TableCell>
                <TableCell>{getStatusBadge(idevid.status)}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatDate(idevid.issuedAt)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-muted-foreground">
                      {formatDate(idevid.expiresAt)}
                    </span>
                    {isExpiringSoon(idevid.expiresAt) && (
                      <AlertCircle className="h-4 w-4 text-orange-500" aria-label="Expiring soon" />
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={loadingId === idevid.id}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                        <span className="sr-only">Open menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => router.push(`/devices/idevid/${idevid.id}`)}
                      >
                        <Eye className="mr-2 h-4 w-4" />
                        View Details
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleDownload(idevid)}>
                        <Download className="mr-2 h-4 w-4" />
                        Download Certificate
                      </DropdownMenuItem>
                      {idevid.status === 'active' && (
                        <>
                          <DropdownMenuItem onClick={() => handleRenew(idevid)}>
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Renew Certificate
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleRevoke(idevid)}
                            className="text-destructive"
                          >
                            <XCircle className="mr-2 h-4 w-4" />
                            Revoke Certificate
                          </DropdownMenuItem>
                        </>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}

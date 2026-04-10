'use client';

/**
 * VTPMTable Component
 * DataTable for displaying and managing vTPM instances
 */

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  MoreHorizontal,
  Eye,
  Lock,
  ArrowRightLeft,
  Trash2,
  Pause,
  Play,
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
import { useVTPM, useMutation } from '@/hooks';
import type { VTPM } from '@/types/device';

interface VTPMTableProps {
  vtpms: VTPM[];
  onVTPMChange?: () => void;
}

export function VTPMTable({ vtpms, onVTPMChange }: VTPMTableProps) {
  const router = useRouter();
  const { toast } = useToast();
  const vtpmService = useVTPM();
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const deleteMutation = useMutation(
    async (id: string) => {
      return await vtpmService.deleteBundle(id);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'vTPM deleted successfully',
        });
        onVTPMChange?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error instanceof Error ? error.message : 'Failed to delete vTPM',
          variant: 'destructive',
        });
      },
    }
  );

  const handleSuspend = async (vtpm: VTPM) => {
    setLoadingId(vtpm.id);
    try {
      // Note: suspend/resume may not be available in SDK, using placeholder
      toast({
        title: 'Info',
        description: 'Suspend operation not yet implemented in SDK',
        variant: 'default',
      });
    } finally {
      setLoadingId(null);
    }
  };

  const handleResume = async (vtpm: VTPM) => {
    setLoadingId(vtpm.id);
    try {
      // Note: suspend/resume may not be available in SDK, using placeholder
      toast({
        title: 'Info',
        description: 'Resume operation not yet implemented in SDK',
        variant: 'default',
      });
    } finally {
      setLoadingId(null);
    }
  };

  const handleDelete = async (vtpm: VTPM) => {
    if (!confirm(`Are you sure you want to delete vTPM ${vtpm.name}? This action cannot be undone.`)) {
      return;
    }

    setLoadingId(vtpm.id);
    try {
      await deleteMutation.mutateAsync(vtpm.id);
    } finally {
      setLoadingId(null);
    }
  };

  const getStateBadge = (state: VTPM['state']) => {
    const variants: Record<VTPM['state'], { variant: 'default' | 'secondary' | 'outline'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      sealed: { variant: 'secondary', label: 'Sealed' },
      migrating: { variant: 'outline', label: 'Migrating' },
      suspended: { variant: 'secondary', label: 'Suspended' },
    };

    const { variant, label } = variants[state];
    return <Badge variant={variant}>{label}</Badge>;
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>VM/Container</TableHead>
            <TableHead>State</TableHead>
            <TableHead>PCR Profile</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {vtpms.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground">
                No vTPM instances found
              </TableCell>
            </TableRow>
          ) : (
            vtpms.map((vtpm) => (
              <TableRow key={vtpm.id}>
                <TableCell className="font-medium">{vtpm.name}</TableCell>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="text-sm">{vtpm.vmName}</span>
                    <span className="text-xs text-muted-foreground">{vtpm.vmId}</span>
                  </div>
                </TableCell>
                <TableCell>{getStateBadge(vtpm.state)}</TableCell>
                <TableCell>
                  <Badge variant="outline">{vtpm.pcrProfile}</Badge>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatDate(vtpm.createdAt)}
                </TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={loadingId === vtpm.id}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                        <span className="sr-only">Open menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => router.push(`/devices/vtpm/${vtpm.id}`)}
                      >
                        <Eye className="mr-2 h-4 w-4" />
                        View Details
                      </DropdownMenuItem>
                      {vtpm.state === 'active' && (
                        <>
                          <DropdownMenuItem
                            onClick={() => router.push(`/devices/vtpm/${vtpm.id}?action=seal`)}
                          >
                            <Lock className="mr-2 h-4 w-4" />
                            Seal Data
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleSuspend(vtpm)}>
                            <Pause className="mr-2 h-4 w-4" />
                            Suspend
                          </DropdownMenuItem>
                        </>
                      )}
                      {vtpm.state === 'suspended' && (
                        <DropdownMenuItem onClick={() => handleResume(vtpm)}>
                          <Play className="mr-2 h-4 w-4" />
                          Resume
                        </DropdownMenuItem>
                      )}
                      {vtpm.state !== 'migrating' && (
                        <DropdownMenuItem
                          onClick={() => router.push(`/devices/vtpm/${vtpm.id}?action=migrate`)}
                        >
                          <ArrowRightLeft className="mr-2 h-4 w-4" />
                          Migrate
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(vtpm)}
                        className="text-destructive"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Delete
                      </DropdownMenuItem>
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

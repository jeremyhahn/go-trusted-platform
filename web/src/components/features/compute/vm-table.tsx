'use client';

import { useState } from 'react';
import { MoreHorizontal, Play, Square, RotateCw, Trash2, Monitor } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
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
import { Badge } from '@/components/ui/badge';
import { useCompute, useMutation, useToast, MutationError } from '@/hooks';
import type { VM } from '@/types/infrastructure';

interface VMTableProps {
  vms: VM[];
  onRefresh: () => void;
  onConsole?: (vm: VM) => void;
}

const statusColors: Record<VM['status'], string> = {
  running: 'bg-green-500/10 text-green-500 border-green-500/20',
  stopped: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  suspended: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  creating: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
};

export function VMTable({ vms, onRefresh, onConsole }: VMTableProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const compute = useCompute();
  const { toast } = useToast();

  const startVMMutation = useMutation(
    (vmId: string) => compute.startVM(vmId),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM started successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to start VM: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const stopVMMutation = useMutation(
    (vmId: string) => compute.stopVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM stopped successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to stop VM: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const rebootVMMutation = useMutation(
    (vmId: string) => compute.rebootVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM rebooted successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to reboot VM: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const deleteVMMutation = useMutation(
    (vmId: string) => compute.deleteVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM deleted successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to delete VM: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const handleStart = (vmId: string) => {
    setLoading(vmId);
    startVMMutation.mutate(vmId);
  };

  const handleStop = (vmId: string) => {
    setLoading(vmId);
    stopVMMutation.mutate(vmId);
  };

  const handleReboot = (vmId: string) => {
    setLoading(vmId);
    rebootVMMutation.mutate(vmId);
  };

  const handleDelete = (vmId: string) => {
    setLoading(vmId);
    deleteVMMutation.mutate(vmId);
  };

  const formatMemory = (mb: number) => {
    if (mb >= 1024) {
      return `${(mb / 1024).toFixed(1)} GB`;
    }
    return `${mb} MB`;
  };

  const formatStorage = (mb: number) => {
    if (mb >= 1024) {
      return `${(mb / 1024).toFixed(1)} GB`;
    }
    return `${mb} MB`;
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>vCPUs</TableHead>
            <TableHead>Memory</TableHead>
            <TableHead>Storage</TableHead>
            <TableHead>IP Address</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {vms.length === 0 ? (
            <TableRow>
              <TableCell colSpan={8} className="text-center text-muted-foreground">
                No virtual machines found
              </TableCell>
            </TableRow>
          ) : (
            vms.map((vm) => (
              <TableRow key={vm.id}>
                <TableCell className="font-medium">{vm.name}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={statusColors[vm.status]}>
                    {vm.status}
                  </Badge>
                </TableCell>
                <TableCell>{vm.vcpus}</TableCell>
                <TableCell>{formatMemory(vm.memoryMB)}</TableCell>
                <TableCell>{formatStorage(vm.storageMB)}</TableCell>
                <TableCell className="font-mono text-sm">
                  {vm.ipAddress || '-'}
                </TableCell>
                <TableCell>
                  {formatDistanceToNow(new Date(vm.createdAt), { addSuffix: true })}
                </TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={loading === vm.id}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {vm.status !== 'running' && (
                        <DropdownMenuItem
                          onClick={() => handleStart(vm.id)}
                        >
                          <Play className="mr-2 h-4 w-4" />
                          Start
                        </DropdownMenuItem>
                      )}
                      {vm.status === 'running' && (
                        <>
                          <DropdownMenuItem
                            onClick={() => handleStop(vm.id)}
                          >
                            <Square className="mr-2 h-4 w-4" />
                            Stop
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() => handleReboot(vm.id)}
                          >
                            <RotateCw className="mr-2 h-4 w-4" />
                            Reboot
                          </DropdownMenuItem>
                          {onConsole && (
                            <DropdownMenuItem onClick={() => onConsole(vm)}>
                              <Monitor className="mr-2 h-4 w-4" />
                              Console
                            </DropdownMenuItem>
                          )}
                        </>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(vm.id)}
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

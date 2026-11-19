'use client';

import { useState } from 'react';
import Link from 'next/link';
import { MoreHorizontal, Play, Square, Terminal, FileText, Trash2 } from 'lucide-react';
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
import type { Container } from '@/types/infrastructure';

interface ContainerTableProps {
  containers: Container[];
  onRefresh: () => void;
  onLogs?: (container: Container) => void;
  onShell?: (container: Container) => void;
}

const statusColors: Record<Container['status'], string> = {
  running: 'bg-green-500/10 text-green-500 border-green-500/20',
  stopped: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  creating: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  error: 'bg-red-500/10 text-red-500 border-red-500/20',
};

export function ContainerTable({
  containers,
  onRefresh,
  onLogs,
  onShell,
}: ContainerTableProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const compute = useCompute();
  const { toast } = useToast();

  const startContainerMutation = useMutation(
    (containerId: string) => compute.startContainer(containerId),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Container started successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to start container: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const stopContainerMutation = useMutation(
    (containerId: string) => compute.stopContainer({ id: containerId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Container stopped successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to stop container: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const deleteContainerMutation = useMutation(
    (containerId: string) => compute.deleteContainer({ id: containerId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Container deleted successfully',
        });
        setLoading(null);
        onRefresh();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to delete container: ${error.message}`,
          variant: 'destructive',
        });
        setLoading(null);
      },
    }
  );

  const handleStart = (containerId: string) => {
    setLoading(containerId);
    startContainerMutation.mutate(containerId);
  };

  const handleStop = (containerId: string) => {
    setLoading(containerId);
    stopContainerMutation.mutate(containerId);
  };

  const handleDelete = (containerId: string) => {
    setLoading(containerId);
    deleteContainerMutation.mutate(containerId);
  };

  const formatPorts = (ports: Container['ports']) => {
    if (ports.length === 0) return '-';
    return ports.map((p) => `${p.host}:${p.container}/${p.protocol}`).join(', ');
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Image</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Ports</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {containers.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground">
                No containers found
              </TableCell>
            </TableRow>
          ) : (
            containers.map((container) => (
              <TableRow key={container.id}>
                <TableCell className="font-medium">
                  <Link href={`/compute/containers/${encodeURIComponent(container.id)}`} className="hover:underline">
                    {container.name}
                  </Link>
                </TableCell>
                <TableCell className="font-mono text-sm">{container.image}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={statusColors[container.status]}>
                    {container.status}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {formatPorts(container.ports)}
                </TableCell>
                <TableCell>
                  {formatDistanceToNow(new Date(container.createdAt), {
                    addSuffix: true,
                  })}
                </TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={loading === container.id}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {container.status !== 'running' && (
                        <DropdownMenuItem
                          onClick={() => handleStart(container.id)}
                        >
                          <Play className="mr-2 h-4 w-4" />
                          Start
                        </DropdownMenuItem>
                      )}
                      {container.status === 'running' && (
                        <>
                          <DropdownMenuItem
                            onClick={() => handleStop(container.id)}
                          >
                            <Square className="mr-2 h-4 w-4" />
                            Stop
                          </DropdownMenuItem>
                          {onLogs && (
                            <DropdownMenuItem onClick={() => onLogs(container)}>
                              <FileText className="mr-2 h-4 w-4" />
                              Logs
                            </DropdownMenuItem>
                          )}
                          {onShell && (
                            <DropdownMenuItem onClick={() => onShell(container)}>
                              <Terminal className="mr-2 h-4 w-4" />
                              Shell
                            </DropdownMenuItem>
                          )}
                        </>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(container.id)}
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

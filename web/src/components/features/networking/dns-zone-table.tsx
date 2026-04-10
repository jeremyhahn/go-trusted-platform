'use client';

import { MoreHorizontal, Eye, Trash2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
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
import { useDNS, useMutation, useToast } from '@/hooks';
import type { DNSZone } from '@/types/infrastructure';

interface DNSZoneTableProps {
  zones: DNSZone[];
  onRefresh: () => void;
}

export function DNSZoneTable({ zones, onRefresh }: DNSZoneTableProps) {
  const { toast } = useToast();
  const router = useRouter();
  const dns = useDNS();

  const deleteMutation = useMutation(
    (zoneName: string) => dns.deleteZone(zoneName),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'DNS zone deleted successfully',
        });
        onRefresh();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to delete zone: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const handleDelete = (name: string) => {
    deleteMutation.mutate(name);
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Zone Name</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Records</TableHead>
            <TableHead>Serial</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {zones.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground">
                No DNS zones found
              </TableCell>
            </TableRow>
          ) : (
            zones.map((zone) => (
              <TableRow key={zone.id}>
                <TableCell className="font-medium font-mono">{zone.name}</TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={
                      zone.type === 'primary'
                        ? 'bg-blue-500/10 text-blue-500 border-blue-500/20'
                        : 'bg-gray-500/10 text-gray-500 border-gray-500/20'
                    }
                  >
                    {zone.type}
                  </Badge>
                </TableCell>
                <TableCell>{zone.recordCount}</TableCell>
                <TableCell className="font-mono text-sm">{zone.serial}</TableCell>
                <TableCell>
                  {formatDistanceToNow(new Date(zone.createdAt), { addSuffix: true })}
                </TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={deleteMutation.isLoading}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => router.push(`/networking/dns/${zone.name}`)}
                      >
                        <Eye className="mr-2 h-4 w-4" />
                        View Records
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(zone.name)}
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

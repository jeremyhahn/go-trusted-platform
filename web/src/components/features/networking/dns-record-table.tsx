'use client';

import { MoreHorizontal, Edit, Trash2 } from 'lucide-react';
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
import { toRecordType } from "@/utils/dns-record-type";
import type { DNSRecord } from '@/types/infrastructure';

interface DNSRecordTableProps {
  zoneName: string;
  records: DNSRecord[];
  onRefresh: () => void;
  onEdit?: (record: DNSRecord) => void;
}

const recordTypeColors: Record<DNSRecord['type'], string> = {
  A: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  AAAA: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
  CNAME: 'bg-green-500/10 text-green-500 border-green-500/20',
  MX: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  TXT: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  NS: 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20',
  SOA: 'bg-pink-500/10 text-pink-500 border-pink-500/20',
  PTR: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/20',
  SRV: 'bg-red-500/10 text-red-500 border-red-500/20',
};

export function DNSRecordTable({
  zoneName,
  records,
  onRefresh,
  onEdit,
}: DNSRecordTableProps) {
  const { toast } = useToast();
  const dns = useDNS();

  const deleteMutation = useMutation(
    ({ type, name }: { type: string; name: string }) => {
      return dns.deleteRecord({
        zoneName,
        type: toRecordType(type),
        name
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'DNS record deleted successfully',
        });
        onRefresh();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to delete record: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const handleDelete = (record: DNSRecord) => {
    deleteMutation.mutate({ type: record.type, name: record.name });
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Value</TableHead>
            <TableHead>TTL</TableHead>
            <TableHead>Priority</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {records.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground">
                No DNS records found
              </TableCell>
            </TableRow>
          ) : (
            records.map((record) => (
              <TableRow key={record.id}>
                <TableCell className="font-medium font-mono">{record.name}</TableCell>
                <TableCell>
                  <Badge variant="outline" className={recordTypeColors[record.type]}>
                    {record.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-sm max-w-md truncate">
                  {record.value}
                </TableCell>
                <TableCell>{record.ttl}s</TableCell>
                <TableCell>{record.priority ?? '-'}</TableCell>
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
                      {onEdit && (
                        <DropdownMenuItem onClick={() => onEdit(record)}>
                          <Edit className="mr-2 h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem
                        onClick={() => handleDelete(record)}
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

'use client';

import { MoreHorizontal, Edit, Trash2, ToggleLeft, ToggleRight } from 'lucide-react';
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
import { useGateway, useMutation, useToast } from '@/hooks';
import type { GatewayRoute } from '@/types/infrastructure';

interface GatewayRoutesTableProps {
  routes: GatewayRoute[];
  onRefresh: () => void;
  onEdit?: (route: GatewayRoute) => void;
}

export function GatewayRoutesTable({
  routes,
  onRefresh,
  onEdit,
}: GatewayRoutesTableProps) {
  const { toast } = useToast();
  const gateway = useGateway();

  const deleteMutation = useMutation(
    async (routeId: string) => {
      // TODO: Add deleteRoute method to gateway service
      // Placeholder implementation
      return { data: { success: true }, error: undefined, success: true };
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Route deleted successfully',
        });
        onRefresh();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to delete route: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const toggleMutation = useMutation(
    async (route: GatewayRoute) => {
      // TODO: Add updateRoute method to gateway service
      // Placeholder implementation
      return { data: { success: true }, error: undefined, success: true };
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Route status updated successfully',
        });
        onRefresh();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to toggle route: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const handleDelete = (routeId: string) => {
    deleteMutation.mutate(routeId);
  };

  const handleToggle = (route: GatewayRoute) => {
    toggleMutation.mutate(route);
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Path</TableHead>
            <TableHead>Method</TableHead>
            <TableHead>Backend</TableHead>
            <TableHead>Rate Limit</TableHead>
            <TableHead>Auth</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Requests</TableHead>
            <TableHead>Avg Latency</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {routes.length === 0 ? (
            <TableRow>
              <TableCell colSpan={9} className="text-center text-muted-foreground">
                No routes found
              </TableCell>
            </TableRow>
          ) : (
            routes.map((route) => (
              <TableRow key={route.id}>
                <TableCell className="font-medium font-mono">{route.path}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-xs">
                    {route.method}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-sm">{route.backend}</TableCell>
                <TableCell>
                  {route.rateLimit
                    ? `${route.rateLimit}/${route.rateLimitWindow || '1m'}`
                    : '-'}
                </TableCell>
                <TableCell>
                  {route.authRequired ? (
                    <Badge
                      variant="outline"
                      className="bg-green-500/10 text-green-500 border-green-500/20"
                    >
                      Required
                    </Badge>
                  ) : (
                    <Badge
                      variant="outline"
                      className="bg-gray-500/10 text-gray-500 border-gray-500/20"
                    >
                      None
                    </Badge>
                  )}
                </TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={
                      route.status === 'active'
                        ? 'bg-green-500/10 text-green-500 border-green-500/20'
                        : 'bg-gray-500/10 text-gray-500 border-gray-500/20'
                    }
                  >
                    {route.status}
                  </Badge>
                </TableCell>
                <TableCell>
                  {route.requestsTotal.toLocaleString()}
                  <span className="text-muted-foreground text-xs ml-1">
                    ({route.requestsPerSecond.toFixed(2)}/s)
                  </span>
                </TableCell>
                <TableCell>{route.avgLatencyMs.toFixed(0)}ms</TableCell>
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={deleteMutation.isLoading || toggleMutation.isLoading}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => handleToggle(route)}>
                        {route.status === 'active' ? (
                          <>
                            <ToggleLeft className="mr-2 h-4 w-4" />
                            Disable
                          </>
                        ) : (
                          <>
                            <ToggleRight className="mr-2 h-4 w-4" />
                            Enable
                          </>
                        )}
                      </DropdownMenuItem>
                      {onEdit && (
                        <DropdownMenuItem onClick={() => onEdit(route)}>
                          <Edit className="mr-2 h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(route.id)}
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

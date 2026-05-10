'use client';

/**
 * Provisioning Sessions Dashboard
 * Live view of active device provisioning sessions with real-time status
 */

import { useState, useMemo, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  RefreshCw,
  MoreHorizontal,
  Eye,
  CheckCircle2,
  Clock,
  XCircle,
  AlertCircle,
  Loader2,
  Activity,
  Cpu,
  Network,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast, useProvisioningSessions, useDeviceTemplates } from '@/hooks';
import type { ProvisioningSession } from 'trusted-platform-sdk';

// ============================================================================
// Types
// ============================================================================

type SessionStatus = 'pending' | 'fulfilled' | 'expired';

interface SessionFilters {
  status?: SessionStatus | 'all';
  search?: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function getSessionStatus(session: ProvisioningSession): SessionStatus {
  if (session.fulfilled) return 'fulfilled';
  if (new Date(session.expiresAt) < new Date()) return 'expired';
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
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function truncateId(id: string) {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}...${id.slice(-4)}`;
}

// ============================================================================
// Assign Template Dialog
// ============================================================================

interface AssignTemplateDialogProps {
  session: ProvisioningSession | null;
  onClose: () => void;
  onAssign: (sessionId: string, profileId: number) => Promise<void>;
  isLoading: boolean;
}

function AssignTemplateDialog({ session, onClose, onAssign, isLoading }: AssignTemplateDialogProps) {
  const { templates, isLoading: templatesLoading } = useDeviceTemplates();
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const { toast } = useToast();
  const router = useRouter();

  if (!session) return null;

  const handleAssignFromTemplate = () => {
    if (!selectedTemplateId) {
      toast({
        title: 'No template selected',
        description: 'Please select a template to assign',
        variant: 'destructive',
      });
      return;
    }
    router.push(
      `/devices/templates/${selectedTemplateId}/create-profile?ekSerial=${session.ekSerial ?? ''}&macAddress=${session.macAddress ?? ''}&sessionId=${session.id}`
    );
  };

  return (
    <Dialog open={session !== null} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Assign Template to Session</DialogTitle>
          <DialogDescription>
            Choose a template to create a profile for this device. The provisioning
            session will be fulfilled automatically after the profile is created.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid gap-2 text-sm">
            {session.ekSerial && (
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">EK Serial</span>
                <span className="font-mono">{session.ekSerial}</span>
              </div>
            )}
            {session.macAddress && (
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">MAC Address</span>
                <span className="font-mono">{session.macAddress}</span>
              </div>
            )}
          </div>
          <div className="grid gap-2">
            <Label>Select Template</Label>
            {templatesLoading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading templates...
              </div>
            ) : (
              <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose a device template..." />
                </SelectTrigger>
                <SelectContent>
                  {templates
                    .filter((t) => t.id != null && String(t.id) !== '')
                    .map((t) => (
                      <SelectItem key={t.id} value={String(t.id)}>
                        {t.name} ({t.role})
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            Cancel
          </Button>
          <Button
            onClick={handleAssignFromTemplate}
            disabled={!selectedTemplateId || isLoading}
          >
            {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Create Profile from Template
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================================
// Main Component
// ============================================================================

const POLL_INTERVAL_MS = 10_000;

export default function ProvisioningSessionsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [filters, setFilters] = useState<SessionFilters>({ status: 'all' });
  const [assignSession, setAssignSession] = useState<ProvisioningSession | null>(null);

  const { sessions, isLoading, error, refetch, fulfill } = useProvisioningSessions();

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refetch();
    }, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [refetch]);

  // Filtered sessions
  const filteredSessions = useMemo(() => {
    return sessions.filter((session) => {
      const status = getSessionStatus(session);
      if (filters.status && filters.status !== 'all' && status !== filters.status) return false;
      if (filters.search) {
        const search = filters.search.toLowerCase();
        return (
          session.id.toLowerCase().includes(search) ||
          session.ekSerial?.toLowerCase().includes(search) ||
          session.macAddress?.toLowerCase().includes(search)
        );
      }
      return true;
    });
  }, [sessions, filters]);

  // Statistics
  const stats = useMemo(() => {
    const pending = sessions.filter((s) => getSessionStatus(s) === 'pending').length;
    const fulfilled = sessions.filter((s) => getSessionStatus(s) === 'fulfilled').length;
    const expired = sessions.filter((s) => getSessionStatus(s) === 'expired').length;
    return { total: sessions.length, pending, fulfilled, expired };
  }, [sessions]);

  const handleFilterChange = (key: keyof SessionFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  const handleAssign = async (sessionId: string, profileId: number) => {
    try {
      await fulfill.mutateAsync({ sessionId, profileId });
      toast({
        title: 'Session fulfilled',
        description: 'The provisioning session has been fulfilled',
        variant: 'success',
      });
      setAssignSession(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Error fulfilling session',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Sessions</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetch()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Provisioning Sessions</h1>
          <p className="text-muted-foreground">
            Live dashboard of device provisioning sessions — auto-refreshes every 10 seconds
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Sessions</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">All provisioning sessions</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
            <Clock className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
              {stats.pending}
            </div>
            <p className="text-xs text-muted-foreground">Awaiting profile assignment</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Fulfilled</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.fulfilled}
            </div>
            <p className="text-xs text-muted-foreground">Successfully provisioned</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Expired</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {stats.expired}
            </div>
            <p className="text-xs text-muted-foreground">Timed out without fulfillment</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <div className="flex flex-1 items-center gap-4">
          <Input
            placeholder="Search by session ID, EK serial, or MAC..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.status || 'all'}
            onValueChange={(value) => handleFilterChange('status', value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="fulfilled">Fulfilled</SelectItem>
              <SelectItem value="expired">Expired</SelectItem>
            </SelectContent>
          </Select>
          {(filters.status !== 'all' || filters.search) && (
            <Button variant="ghost" onClick={() => setFilters({ status: 'all' })}>
              Clear filters
            </Button>
          )}
        </div>
      </div>

      {/* Sessions Table */}
      {isLoading && sessions.length === 0 ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin mx-auto" />
            <p className="mt-2 text-sm text-muted-foreground">Loading sessions...</p>
          </div>
        </div>
      ) : (
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session ID</TableHead>
                <TableHead>
                  <div className="flex items-center gap-1">
                    <Cpu className="h-4 w-4" />
                    EK Serial
                  </div>
                </TableHead>
                <TableHead>
                  <div className="flex items-center gap-1">
                    <Network className="h-4 w-4" />
                    MAC Address
                  </div>
                </TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredSessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {filters.search || (filters.status && filters.status !== 'all')
                      ? 'No sessions match your filters'
                      : 'No provisioning sessions found'}
                  </TableCell>
                </TableRow>
              ) : (
                filteredSessions.map((session) => {
                  const status = getSessionStatus(session);
                  return (
                    <TableRow key={session.id}>
                      <TableCell>
                        <span
                          className="font-mono text-sm cursor-pointer hover:underline"
                          title={session.id}
                          onClick={() => router.push(`/provisioning/sessions/${session.id}`)}
                        >
                          {truncateId(session.id)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-sm text-muted-foreground">
                          {session.ekSerial || '-'}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-sm text-muted-foreground">
                          {session.macAddress || '-'}
                        </span>
                      </TableCell>
                      <TableCell>{getStatusBadge(status)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(session.createdAt)}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(session.expiresAt)}
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                              <span className="sr-only">Open menu</span>
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() =>
                                router.push(`/provisioning/sessions/${session.id}`)
                              }
                            >
                              <Eye className="mr-2 h-4 w-4" />
                              View Session
                            </DropdownMenuItem>
                            {status === 'pending' && (
                              <DropdownMenuItem
                                onClick={() => setAssignSession(session)}
                              >
                                <CheckCircle2 className="mr-2 h-4 w-4" />
                                Assign Template
                              </DropdownMenuItem>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Assign Template Dialog */}
      <AssignTemplateDialog
        session={assignSession}
        onClose={() => setAssignSession(null)}
        onAssign={handleAssign}
        isLoading={fulfill.isLoading}
      />
    </div>
  );
}

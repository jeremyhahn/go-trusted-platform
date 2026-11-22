'use client';

/**
 * IDevID List Page
 * Display all IDevID certificates with filtering and management capabilities
 */

import { useState, useEffect } from 'react';
import { Plus, Filter, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { IDevIDTable } from '@/components/features/devices/idevid-table';
import { IDevIDForm } from '@/components/features/devices/idevid-form';
import { useToast } from '@/hooks/use-toast';
import { useIDevID } from '@/hooks';
import type { IDevID, IDevIDFilters } from '@/types/device';

export default function IDevIDPage() {
  const { toast } = useToast();
  const idevid = useIDevID();
  const [idevids, setIDevIDs] = useState<IDevID[]>([]);
  const [expiringCount, setExpiringCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [filters, setFilters] = useState<IDevIDFilters>({});

  // The settle functions apply one read from their promise callbacks, so the
  // effect starts them without a synchronous setState; fetchIDevIDs adds the
  // loading flag for a re-read.
  const settleIDevIDs = () =>
    fetch('/api/v1/idevid')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error('Failed to fetch IDevID certificates');
        }
        const data = await response.json();
        setIDevIDs(data.idevids || []);
      })
      .catch((error: unknown) => {
        toast({
          title: 'Error',
          description: error instanceof Error ? error.message : 'Failed to fetch IDevID certificates',
          variant: 'destructive',
        });
        setIDevIDs([]);
      })
      .finally(() => setIsLoading(false));

  const fetchIDevIDs = async () => {
    setIsLoading(true);
    await settleIDevIDs();
  };

  const settleExpiringCertificates = () =>
    fetch('/api/v1/idevid/expiring')
      .then(async (response) => {
        if (response.ok) {
          const data = await response.json();
          setExpiringCount(data.count || 0);
        }
      })
      .catch((error: unknown) => {
        // Silent fail - this is just a warning
        console.error('Failed to fetch expiring certificates:', error);
      });

  useEffect(() => {
    void settleIDevIDs();
    void settleExpiringCertificates();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  const handleSuccess = () => {
    setIsDialogOpen(false);
    fetchIDevIDs();
  };

  const handleFilterChange = (key: keyof IDevIDFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">IDevID Certificates</h1>
          <p className="text-muted-foreground">
            Manage device identity certificates (IEEE 802.1AR)
          </p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Issue IDevID
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Issue IDevID Certificate</DialogTitle>
              <DialogDescription>
                Issue a new device identity certificate for a registered device
              </DialogDescription>
            </DialogHeader>
            <IDevIDForm
              onSuccess={handleSuccess}
              onCancel={() => setIsDialogOpen(false)}
            />
          </DialogContent>
        </Dialog>
      </div>

      {expiringCount > 0 && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Certificates Expiring Soon</AlertTitle>
          <AlertDescription>
            {expiringCount} certificate{expiringCount > 1 ? 's' : ''} will expire within the next 30 days.
            Consider renewing them to avoid service interruption.
          </AlertDescription>
        </Alert>
      )}

      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <Filter className="h-5 w-5 text-muted-foreground" />
        <div className="flex flex-1 items-center gap-4">
          <Input
            placeholder="Search certificates..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.status || 'all'}
            onValueChange={(value) => handleFilterChange('status', value === 'all' ? '' : value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="revoked">Revoked</SelectItem>
              <SelectItem value="expired">Expired</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={filters.expiringDays?.toString() || 'all'}
            onValueChange={(value) => {
              const days = value === 'all' ? undefined : parseInt(value);
              setFilters((prev) => ({ ...prev, expiringDays: days }));
            }}
          >
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Expiration" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All certificates</SelectItem>
              <SelectItem value="7">Expiring in 7 days</SelectItem>
              <SelectItem value="30">Expiring in 30 days</SelectItem>
              <SelectItem value="90">Expiring in 90 days</SelectItem>
            </SelectContent>
          </Select>
          {(filters.status || filters.search || filters.expiringDays) && (
            <Button
              variant="ghost"
              onClick={() => setFilters({})}
            >
              Clear filters
            </Button>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent motion-reduce:animate-[spin_1.5s_linear_infinite]" />
            <p className="mt-2 text-sm text-muted-foreground">Loading certificates...</p>
          </div>
        </div>
      ) : (
        <IDevIDTable idevids={idevids} onIDevIDChange={fetchIDevIDs} />
      )}
    </div>
  );
}

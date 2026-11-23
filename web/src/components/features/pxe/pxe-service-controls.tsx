'use client';

import { useState } from 'react';
import { Play, Square } from 'lucide-react';
import type { ApiResponse } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Gated } from '@/components/features/capabilities/gated';
import { usePXE, useToast } from '@/hooks';

const START_OP = 'POST /api/v1/pxe/start';
const STOP_OP = 'POST /api/v1/pxe/stop';

export interface PXEServiceControlsProps {
  running: boolean;
  onChanged: () => void;
}

/**
 * PXEServiceControls is the Start/Stop control of the PXE status card: each
 * button is gated on the server route it calls and goes through the SDK
 * PXEService. Stop asks for a confirm first.
 */
export function PXEServiceControls({ running, onChanged }: PXEServiceControlsProps) {
  const pxe = usePXE();
  const { toast } = useToast();
  const [confirmStop, setConfirmStop] = useState(false);
  const [busy, setBusy] = useState(false);

  const write = async (title: string, call: () => Promise<ApiResponse<unknown>>): Promise<void> => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success === false) {
        toast({
          title: 'PXE request failed',
          description: res.error?.message,
          variant: 'destructive',
        });
        return;
      }
      toast({ title, variant: 'success' });
      setConfirmStop(false);
      onChanged();
    } catch (err) {
      toast({
        title: 'PXE request failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  const start = () => write('PXE service started', () => pxe.startService());
  const stop = () => write('PXE service stopped', () => pxe.stopService());

  return (
    <div className="flex gap-2">
      {running ? (
        <Gated op={STOP_OP}>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => setConfirmStop(true)}>
            <Square className="mr-2 h-4 w-4" />
            Stop PXE service
          </Button>
        </Gated>
      ) : (
        <Gated op={START_OP}>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void start()}>
            <Play className="mr-2 h-4 w-4" />
            Start PXE service
          </Button>
        </Gated>
      )}

      <Dialog open={confirmStop} onOpenChange={setConfirmStop}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Stop PXE service?</DialogTitle>
            <DialogDescription>Devices cannot network boot from this node until the service is started again.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmStop(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void stop()} disabled={busy}>
              Stop
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

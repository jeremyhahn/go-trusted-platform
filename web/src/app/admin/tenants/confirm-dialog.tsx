"use client";

import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui";

/** A pending destructive action: what the dialog says and what Confirm runs. */
export interface PendingAction {
  title: string;
  description: string;
  confirmLabel: string;
  run: () => Promise<void>;
}

interface ConfirmDialogProps {
  action: PendingAction | null;
  onClose: () => void;
}

/** ConfirmDialog asks before a destructive tenant action runs. */
export function ConfirmDialog({ action, onClose }: ConfirmDialogProps) {
  return (
    <Dialog open={action !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent data-testid="confirm-dialog">
        <DialogHeader>
          <DialogTitle>{action?.title}</DialogTitle>
          <DialogDescription>{action?.description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            data-testid="confirm-action"
            onClick={async () => {
              const pending = action;
              onClose();
              if (pending) await pending.run();
            }}
          >
            {action?.confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** errorText names the failure of an SDK response for the status line. */
export function errorText(res: { success: boolean; error?: { message?: string } }, fallback: string): string {
  return res.error?.message || fallback;
}

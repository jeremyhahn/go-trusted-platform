"use client";

/**
 * ConfirmAction: a destructive button that opens a confirm dialog and runs
 * the action only after the user confirms.
 */

import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export interface ConfirmActionProps {
  /** Button label */
  label: string;
  /** Dialog title */
  title: string;
  /** Dialog description: what the action destroys */
  description: string;
  /** Runs after the user confirms */
  onConfirm: () => void;
  /** Disables the trigger button */
  disabled?: boolean;
}

export function ConfirmAction({ label, title, description, onConfirm, disabled }: ConfirmActionProps) {
  const [open, setOpen] = React.useState(false);

  return (
    <>
      <Button variant="destructive" onClick={() => setOpen(true)} disabled={disabled}>
        {label}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                setOpen(false);
                onConfirm();
              }}
            >
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Pencil } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { numberFieldProps } from '@/lib/number-field';
import { useDNS, useMutation, useToast } from '@/hooks';
import { Gated } from '@/components/features/capabilities/gated';
import { useCapabilities } from '@/hooks/use-capabilities';

// UpdateZone's route, the op the server's capabilities answer for (#2060).
const UPDATE_ZONE_OP = 'PUT /api/v1/dns/zones/{zone}';

const formSchema = z.object({
  ttl: z
    .number({ error: 'TTL must be a number from 60 to 86400' })
    .int('TTL must be a whole number of seconds')
    .min(60, 'TTL must be at least 60 seconds')
    .max(86400, 'TTL must be at most 86400 seconds'),
  description: z.string().optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface DNSZoneEditDialogProps {
  zoneName: string;
  ttl: number;
  description?: string;
  onSaved: () => void;
}

export function DNSZoneEditDialog({ zoneName, ttl, description, onSaved }: DNSZoneEditDialogProps) {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const dns = useDNS();
  const { capability } = useCapabilities();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { ttl, description: description ?? '' },
  });

  const updateMutation = useMutation(
    (values: FormValues) =>
      dns.updateZone({ name: zoneName, ttl: values.ttl, description: values.description }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Zone updated',
        });
        setOpen(false);
        onSaved();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to update zone: ${error.message}`,
          variant: 'destructive',
        });
      },
    },
  );

  const handleOpenChange = (next: boolean) => {
    if (next) {
      form.reset({ ttl, description: description ?? '' });
    }
    setOpen(next);
  };

  const onSubmit = (values: FormValues) => {
    // A form submitted by Enter must not bypass the gate.
    if (!capability(UPDATE_ZONE_OP).enabled) {
      return;
    }
    updateMutation.mutate(values);
  };

  return (
    <>
      <Gated op={UPDATE_ZONE_OP}>
        <Button variant="outline" onClick={() => handleOpenChange(true)}>
          <Pencil className="mr-2 h-4 w-4" />
          Edit Zone
        </Button>
      </Gated>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit zone {zoneName}</DialogTitle>
            <DialogDescription>Change the zone&apos;s default TTL and its description.</DialogDescription>
          </DialogHeader>
          <Form {...form}>
            <form noValidate onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="ttl"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>TTL</FormLabel>
                    <FormControl>
                      <Input type="number" min={60} max={86400} {...numberFieldProps(field)} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Input {...field} value={field.value ?? ''} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => handleOpenChange(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updateMutation.isLoading}>
                  Save
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </>
  );
}

'use client';

/**
 * VTPMForm Component
 * Form for creating new vTPM instances
 */

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { useVTPM, useMutation } from '@/hooks';

const vtpmFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  vmId: z.string().min(1, 'VM ID is required'),
  vmName: z.string().min(1, 'VM name is required'),
  description: z.string().optional(),
  pcrProfile: z.string().optional(),
});

type VTPMFormValues = z.infer<typeof vtpmFormSchema>;

interface VTPMFormProps {
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function VTPMForm({ onSuccess, onCancel }: VTPMFormProps) {
  const { toast } = useToast();
  const vtpm = useVTPM();

  const form = useForm<VTPMFormValues>({
    resolver: zodResolver(vtpmFormSchema),
    defaultValues: {
      name: '',
      vmId: '',
      vmName: '',
      description: '',
      pcrProfile: 'default',
    },
  });

  const createMutation = useMutation(
    async (values: VTPMFormValues) => {
      return await vtpm.createBundle({
        options: {
          hostname: values.vmName,
          // Add other vTPM configuration options as needed
        }
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'vTPM instance created successfully',
        });
        form.reset();
        onSuccess?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to create vTPM',
          variant: 'destructive',
        });
      },
    }
  );

  const onSubmit = async (values: VTPMFormValues) => {
    createMutation.mutate(values);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>vTPM Name</FormLabel>
              <FormControl>
                <Input placeholder="my-vtpm" {...field} />
              </FormControl>
              <FormDescription>
                A unique name to identify this vTPM instance
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="vmId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>VM/Container ID</FormLabel>
                <FormControl>
                  <Input placeholder="vm-123456" {...field} />
                </FormControl>
                <FormDescription>
                  Virtual machine or container identifier
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="vmName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>VM/Container Name</FormLabel>
                <FormControl>
                  <Input placeholder="my-vm" {...field} />
                </FormControl>
                <FormDescription>
                  Display name of the VM/container
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="pcrProfile"
          render={({ field }) => (
            <FormItem>
              <FormLabel>PCR Profile</FormLabel>
              <FormControl>
                <Input placeholder="default" {...field} />
              </FormControl>
              <FormDescription>
                PCR configuration profile to use (default: standard profile)
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description (Optional)</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Additional information about this vTPM instance"
                  className="resize-none"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end gap-4">
          {onCancel && (
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={createMutation.isLoading}>
            {createMutation.isLoading ? 'Creating...' : 'Create vTPM'}
          </Button>
        </div>
      </form>
    </Form>
  );
}

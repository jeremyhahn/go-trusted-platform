'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
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
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useCompute, useMutation, useToast, MutationError } from '@/hooks';

const formSchema = z.object({
  name: z.string().min(1, 'Name is required').max(64, 'Name too long'),
  description: z.string().optional(),
  osType: z.string().min(1, 'OS type is required'),
  vcpus: z.coerce.number().min(1).max(64),
  memoryMB: z.coerce.number().min(512).max(524288),
  storageMB: z.coerce.number().min(1024).max(10485760),
  networkId: z.string().optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface VMFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

export function VMForm({ open, onOpenChange, onSuccess }: VMFormProps) {
  const compute = useCompute();
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema) as any, // zod 4 input/output split on coerced number fields (#451)
    defaultValues: {
      name: '',
      description: '',
      osType: 'linux',
      vcpus: 2,
      memoryMB: 2048,
      storageMB: 20480,
      networkId: '',
    },
  });

  const createVMMutation = useMutation(
    (values: FormValues) => {
      // Transform form values to SDK request format
      const config = {
        name: values.name,
        cpu: { cores: values.vcpus },
        memory: { sizeMb: values.memoryMB },
        disks: [{
          path: `/data/${values.name}.qcow2`,
          type: 'QCOW2' as const,
          sizeGb: Math.ceil(values.storageMB / 1024),
        }],
        networks: values.networkId ? [{ bridge: values.networkId }] : [],
      };
      return compute.createVM({ config });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Virtual machine created successfully',
        });
        form.reset();
        onOpenChange(false);
        onSuccess();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to create VM: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const onSubmit = (values: FormValues) => {
    createVMMutation.mutate(values);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Create Virtual Machine</DialogTitle>
          <DialogDescription>
            Create a new virtual machine with the specified configuration.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="my-vm" {...field} />
                  </FormControl>
                  <FormDescription>Unique name for the VM</FormDescription>
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
                    <Textarea
                      placeholder="Optional description"
                      className="resize-none"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="osType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Operating System</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select OS type" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="linux">Linux</SelectItem>
                      <SelectItem value="windows">Windows</SelectItem>
                      <SelectItem value="bsd">BSD</SelectItem>
                      <SelectItem value="other">Other</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-3 gap-4">
              <FormField
                control={form.control}
                name="vcpus"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>vCPUs</FormLabel>
                    <FormControl>
                      <Input type="number" min={1} max={64} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="memoryMB"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Memory (MB)</FormLabel>
                    <FormControl>
                      <Input type="number" min={512} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="storageMB"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Storage (MB)</FormLabel>
                    <FormControl>
                      <Input type="number" min={1024} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={createVMMutation.isLoading}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createVMMutation.isLoading}>
                {createVMMutation.isLoading ? 'Creating...' : 'Create VM'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

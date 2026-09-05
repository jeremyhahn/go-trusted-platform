'use client';

/**
 * DeviceForm Component
 * Form for registering new devices
 */

import { useState } from 'react';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { useDevice, useMutation } from '@/hooks';
import type { RegisterDeviceInput } from '@/types/device';

const deviceFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  type: z.enum(['physical', 'virtual']),
  serial: z.string().optional(),
  description: z.string().optional(),
  tpmManufacturer: z.string().optional(),
  tpmVersion: z.string().optional(),
  tpmFirmwareVersion: z.string().optional(),
});

type DeviceFormValues = z.infer<typeof deviceFormSchema>;

interface DeviceFormProps {
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function DeviceForm({ onSuccess, onCancel }: DeviceFormProps) {
  const { toast } = useToast();
  const device = useDevice();

  const form = useForm<DeviceFormValues>({
    resolver: zodResolver(deviceFormSchema),
    defaultValues: {
      name: '',
      type: 'physical',
      serial: '',
      description: '',
      tpmManufacturer: '',
      tpmVersion: '',
      tpmFirmwareVersion: '',
    },
  });

  const registerMutation = useMutation(
    async (values: DeviceFormValues) => {
      // Sends fields neither the SDK CreateDeviceRequest nor the REST DeviceRegisterRequest declare — #455.
      const requestData: any = {
        device: {
          serial: values.serial || undefined,
          name: values.name,
          // Add other device fields as needed
        }
      };

      return await device.createDevice(requestData);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Device registered successfully',
        });
        form.reset();
        onSuccess?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error instanceof Error ? error.message : 'Failed to register device',
          variant: 'destructive',
        });
      },
    }
  );

  const onSubmit = async (values: DeviceFormValues) => {
    registerMutation.mutate(values);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Device Name</FormLabel>
              <FormControl>
                <Input placeholder="my-device" {...field} />
              </FormControl>
              <FormDescription>
                A unique name to identify this device
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="type"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Device Type</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select device type" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="physical">Physical Device</SelectItem>
                  <SelectItem value="virtual">Virtual Device</SelectItem>
                </SelectContent>
              </Select>
              <FormDescription>
                Physical hardware or virtual machine
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="serial"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Serial Number (Optional)</FormLabel>
              <FormControl>
                <Input placeholder="SN123456789" {...field} />
              </FormControl>
              <FormDescription>
                Device serial number if available
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
                  placeholder="Additional information about this device"
                  className="resize-none"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="space-y-4 rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium">TPM Information (Optional)</h3>

          <FormField
            control={form.control}
            name="tpmManufacturer"
            render={({ field }) => (
              <FormItem>
                <FormLabel>TPM Manufacturer</FormLabel>
                <FormControl>
                  <Input placeholder="e.g., Infineon, STMicroelectronics" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="tpmVersion"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>TPM Version</FormLabel>
                  <FormControl>
                    <Input placeholder="2.0" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="tpmFirmwareVersion"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Firmware Version</FormLabel>
                  <FormControl>
                    <Input placeholder="7.85" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        </div>

        <div className="flex justify-end gap-4">
          {onCancel && (
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={registerMutation.isLoading}>
            {registerMutation.isLoading ? 'Registering...' : 'Register Device'}
          </Button>
        </div>
      </form>
    </Form>
  );
}

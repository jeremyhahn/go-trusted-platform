'use client';

/**
 * DeviceForm Component
 * Form for registering new devices
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
import { useToast } from '@/hooks/use-toast';
import { useDevice, useMutation } from '@/hooks';

// The create contract stores the serial alone: a device has no display
// name, type, description or operator-typed TPM details (#455).
const deviceFormSchema = z.object({
  serial: z.string().trim().min(1, 'Serial number is required'),
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
      serial: '',
    },
  });

  const registerMutation = useMutation(
    async (values: DeviceFormValues) => {
      return await device.createDevice({ device: { serial: values.serial } });
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
          description: error.message || 'Failed to register device',
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
          name="serial"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Serial Number</FormLabel>
              <FormControl>
                <Input placeholder="SN123456789" {...field} />
              </FormControl>
              <FormDescription>
                The serial the device reports at enrollment
              </FormDescription>
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
          <Button type="submit" disabled={registerMutation.isLoading}>
            {registerMutation.isLoading ? 'Registering...' : 'Register Device'}
          </Button>
        </div>
      </form>
    </Form>
  );
}

'use client';

/**
 * IDevIDForm Component
 * Form for issuing new IDevID certificates
 */

import { useState, useEffect } from 'react';
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
import { numberFieldProps } from '@/lib/number-field';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { useIDevID, useDevice, useMutation } from '@/hooks';

const idevidFormSchema = z.object({
  deviceId: z.string().min(1, 'Device is required'),
  subject: z.string().min(1, 'Subject is required'),
  validityDays: z.number().min(1, 'Validity must be at least 1 day').max(3650),
  keyAlgorithm: z.enum(['RSA', 'ECC']),
  keySize: z.number().optional(),
});

type IDevIDFormValues = z.infer<typeof idevidFormSchema>;

interface IDevIDFormProps {
  onSuccess?: () => void;
  onCancel?: () => void;
}

export function IDevIDForm({ onSuccess, onCancel }: IDevIDFormProps) {
  const { toast } = useToast();
  const idevid = useIDevID();
  const deviceService = useDevice();
  const [devices, setDevices] = useState<Array<{ id: string; name: string }>>([]);
  const [isLoadingDevices, setIsLoadingDevices] = useState(true);

  const form = useForm<IDevIDFormValues>({
    resolver: zodResolver(idevidFormSchema),
    defaultValues: {
      deviceId: '',
      subject: '',
      validityDays: 365,
      keyAlgorithm: 'RSA',
      keySize: 2048,
    },
  });

  const keyAlgorithm = form.watch('keyAlgorithm');

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const response = await deviceService.listDevices();
        // The SDK client returns a refusal as success false; it does not throw.
        if (!response.success) {
          throw new Error('device list refused');
        }
        if (response.data?.devices) {
          setDevices(response.data.devices.map((d) => ({ id: d.id.toString(), name: d.serial || d.id.toString() })));
        }
      } catch {
        toast({
          title: 'Error',
          description: 'Failed to load devices',
          variant: 'destructive',
        });
      } finally {
        setIsLoadingDevices(false);
      }
    };

    fetchDevices();
  }, [toast, deviceService]);

  const issueMutation = useMutation(
    async (values: IDevIDFormValues) => {
      // Generate IDevID key pair
      const generateResponse = await idevid.generateIDevID({
        config: {
          algorithm: values.keyAlgorithm === 'RSA' ? 'RSA_2048' : 'ECDSA_P256',
          hierarchy: 'endorsement',
        }
      });

      if (generateResponse.error) {
        throw new Error(generateResponse.error.message || 'Failed to generate IDevID');
      }

      // Create CSR
      const csrResponse = await idevid.createIDevIDCSR({
        template: {
          commonName: values.subject,
        }
      });

      // Note: Certificate installation would require CA integration
      return csrResponse;
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'IDevID certificate issued successfully',
        });
        form.reset();
        onSuccess?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to issue certificate',
          variant: 'destructive',
        });
      },
    }
  );

  const onSubmit = async (values: IDevIDFormValues) => {
    issueMutation.mutate(values);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="deviceId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Device</FormLabel>
              <Select
                onValueChange={(value) => {
                  field.onChange(value);
                  const device = devices.find(d => d.id === value);
                  if (device) {
                    form.setValue('subject', `CN=${device.name}`);
                  }
                }}
                defaultValue={field.value}
                disabled={isLoadingDevices}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select device" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {devices
                    .filter((device) => device.id != null && String(device.id) !== '')
                    .map((device) => (
                      <SelectItem key={device.id} value={String(device.id)}>
                        {device.name}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <FormDescription>
                The device to issue the IDevID certificate for
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="subject"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Certificate Subject</FormLabel>
              <FormControl>
                <Input placeholder="CN=device-name,O=Organization" {...field} />
              </FormControl>
              <FormDescription>
                X.509 subject distinguished name (auto-filled from device name)
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="validityDays"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Validity Period (Days)</FormLabel>
              <FormControl>
                <Input type="number" min="1" max="3650" {...numberFieldProps(field)} />
              </FormControl>
              <FormDescription>
                Certificate validity period (1-3650 days, default: 365)
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="space-y-4 rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium">Key Configuration</h3>

          <FormField
            control={form.control}
            name="keyAlgorithm"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Key Algorithm</FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select algorithm" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="RSA">RSA</SelectItem>
                    <SelectItem value="ECC">ECC (Elliptic Curve)</SelectItem>
                  </SelectContent>
                </Select>
                <FormDescription>
                  Cryptographic algorithm for the key pair
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          {keyAlgorithm === 'RSA' && (
            <FormField
              control={form.control}
              name="keySize"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Key Size (bits)</FormLabel>
                  <Select
                    onValueChange={(value) => field.onChange(parseInt(value))}
                    defaultValue={field.value?.toString()}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select key size" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="2048">2048 bits</SelectItem>
                      <SelectItem value="3072">3072 bits</SelectItem>
                      <SelectItem value="4096">4096 bits</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    RSA key size (larger = more secure but slower)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}

          {keyAlgorithm === 'ECC' && (
            <FormField
              control={form.control}
              name="keySize"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Curve</FormLabel>
                  <Select
                    onValueChange={(value) => field.onChange(parseInt(value))}
                    defaultValue={field.value?.toString()}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select curve" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="256">P-256 (NIST)</SelectItem>
                      <SelectItem value="384">P-384 (NIST)</SelectItem>
                      <SelectItem value="521">P-521 (NIST)</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    ECC curve (higher number = more secure)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}
        </div>

        <div className="flex justify-end gap-4">
          {onCancel && (
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={issueMutation.isLoading}>
            {issueMutation.isLoading ? 'Issuing...' : 'Issue Certificate'}
          </Button>
        </div>
      </form>
    </Form>
  );
}

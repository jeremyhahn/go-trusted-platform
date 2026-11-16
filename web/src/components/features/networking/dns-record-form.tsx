'use client';

import { useEffect } from 'react';
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
import { numberFieldProps } from '@/lib/number-field';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useDNS, useMutation, useToast } from '@/hooks';
import { toRecordType } from "@/utils/dns-record-type";
import type { DNSRecord } from '@/types/infrastructure';
import type { DNSRecord as SDKDNSRecord } from 'trusted-platform-sdk';

const formSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV'] as const),
  value: z.string().min(1, 'Value is required'),
  ttl: z.number().min(60).max(86400),
  priority: z.number().min(0).optional(),
  weight: z.number().min(0).optional(),
  port: z.number().min(1).max(65535).optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface DNSRecordFormProps {
  zoneName: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
  record?: DNSRecord;
}

export function DNSRecordForm({
  zoneName,
  open,
  onOpenChange,
  onSuccess,
  record,
}: DNSRecordFormProps) {
  const { toast } = useToast();
  const dns = useDNS();
  const isEdit = !!record;

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      type: 'A',
      value: '',
      ttl: 3600,
      priority: undefined,
      weight: undefined,
      port: undefined,
    },
  });

  const createMutation = useMutation(
    (values: FormValues) => dns.addRecord({
      zoneName,
      record: {
        type: values.type,
        a: values.type === 'A' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
        aaaa: values.type === 'AAAA' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
        cname: values.type === 'CNAME' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
        mx: values.type === 'MX' ? { name: values.name, value: values.value, ttl: values.ttl, priority: values.priority || 0 } : undefined,
        txt: values.type === 'TXT' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
        ns: values.type === 'NS' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
        srv: values.type === 'SRV' ? {
          name: values.name,
          target: values.value,
          ttl: values.ttl,
          priority: values.priority || 0,
          weight: values.weight || 0,
          port: values.port || 0
        } : undefined,
      }
    }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'DNS record created successfully',
        });
        form.reset();
        onOpenChange(false);
        onSuccess();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to create record: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const updateMutation = useMutation(
    (values: FormValues) => {
      // Convert infrastructure DNSRecord to SDK DNSRecord
      const oldSDKRecord: SDKDNSRecord = {
        type: toRecordType(record!.type),
        a: record!.type === 'A' ? { name: record!.name, value: record!.value, ttl: record!.ttl } : undefined,
        aaaa: record!.type === 'AAAA' ? { name: record!.name, value: record!.value, ttl: record!.ttl } : undefined,
        cname: record!.type === 'CNAME' ? { name: record!.name, value: record!.value, ttl: record!.ttl } : undefined,
        mx: record!.type === 'MX' ? { name: record!.name, value: record!.value, ttl: record!.ttl, priority: record!.priority || 0 } : undefined,
        txt: record!.type === 'TXT' ? { name: record!.name, value: record!.value, ttl: record!.ttl } : undefined,
        ns: record!.type === 'NS' ? { name: record!.name, value: record!.value, ttl: record!.ttl } : undefined,
        srv: record!.type === 'SRV' ? {
          name: record!.name,
          target: record!.value,
          ttl: record!.ttl,
          priority: record!.priority || 0,
          weight: record!.weight || 0,
          port: record!.port || 0
        } : undefined,
      };

      return dns.updateRecord({
        zoneName,
        oldRecord: oldSDKRecord,
        newRecord: {
          type: values.type,
          a: values.type === 'A' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
          aaaa: values.type === 'AAAA' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
          cname: values.type === 'CNAME' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
          mx: values.type === 'MX' ? { name: values.name, value: values.value, ttl: values.ttl, priority: values.priority || 0 } : undefined,
          txt: values.type === 'TXT' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
          ns: values.type === 'NS' ? { name: values.name, value: values.value, ttl: values.ttl } : undefined,
          srv: values.type === 'SRV' ? {
            name: values.name,
            target: values.value,
            ttl: values.ttl,
            priority: values.priority || 0,
            weight: values.weight || 0,
            port: values.port || 0
          } : undefined,
        }
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'DNS record updated successfully',
        });
        form.reset();
        onOpenChange(false);
        onSuccess();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to update record: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const selectedType = form.watch('type');

  useEffect(() => {
    if (record && record.type !== 'PTR' && record.type !== 'SOA') {
      form.reset({
        name: record.name,
        type: record.type as 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SRV',
        value: record.value,
        ttl: record.ttl,
        priority: record.priority,
        weight: record.weight,
        port: record.port,
      });
    }
  }, [record, form]);

  const onSubmit = (values: FormValues) => {
    if (isEdit && record) {
      updateMutation.mutate(values);
    } else {
      createMutation.mutate(values);
    }
  };

  const isLoading = createMutation.isLoading || updateMutation.isLoading;

  const showPriority = ['MX', 'SRV'].includes(selectedType);
  const showSRVFields = selectedType === 'SRV';

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit' : 'Add'} DNS Record</DialogTitle>
          <DialogDescription>
            {isEdit ? 'Update the' : 'Create a new'} DNS record for {zoneName}
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
                    <Input placeholder="www" {...field} />
                  </FormControl>
                  <FormDescription>
                    Record name (use @ for root domain)
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
                  <FormLabel>Type</FormLabel>
                  <Select
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                    disabled={isEdit}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select record type" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="A">A</SelectItem>
                      <SelectItem value="AAAA">AAAA</SelectItem>
                      <SelectItem value="CNAME">CNAME</SelectItem>
                      <SelectItem value="MX">MX</SelectItem>
                      <SelectItem value="TXT">TXT</SelectItem>
                      <SelectItem value="NS">NS</SelectItem>
                      <SelectItem value="SRV">SRV</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="value"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Value</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={
                        selectedType === 'A'
                          ? '192.168.1.1'
                          : selectedType === 'AAAA'
                            ? '2001:db8::1'
                            : selectedType === 'CNAME'
                              ? 'example.com'
                              : selectedType === 'MX'
                                ? 'mail.example.com'
                                : 'Record value'
                      }
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="ttl"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>TTL (seconds)</FormLabel>
                  <FormControl>
                    <Input type="number" min={60} max={86400} {...numberFieldProps(field)} />
                  </FormControl>
                  <FormDescription>Time to live (60-86400)</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {showPriority && (
              <FormField
                control={form.control}
                name="priority"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Priority</FormLabel>
                    <FormControl>
                      <Input type="number" min={0} {...numberFieldProps(field)} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {showSRVFields && (
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="weight"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Weight</FormLabel>
                      <FormControl>
                        <Input type="number" min={0} {...numberFieldProps(field)} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="port"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Port</FormLabel>
                      <FormControl>
                        <Input type="number" min={1} max={65535} {...numberFieldProps(field)} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isLoading}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isLoading}>
                {isLoading ? 'Saving...' : isEdit ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

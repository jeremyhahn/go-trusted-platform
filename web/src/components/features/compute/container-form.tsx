'use client';

import { useForm, useFieldArray } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Plus, X } from 'lucide-react';
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
import { useCompute, useMutation, useToast, MutationError } from '@/hooks';

const portSchema = z.object({
  container: z.number().min(1).max(65535),
  host: z.number().min(1).max(65535),
  protocol: z.enum(['tcp', 'udp']),
});

const formSchema = z.object({
  name: z.string().min(1, 'Name is required').max(64, 'Name too long'),
  image: z.string().min(1, 'Image is required'),
  command: z.string().optional(),
  ports: z.array(portSchema).optional(),
  memoryMB: z.number().min(128).optional(),
  cpuShares: z.number().min(0).max(1024).optional(),
});

type FormValues = z.infer<typeof formSchema>;

interface ContainerFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

export function ContainerForm({ open, onOpenChange, onSuccess }: ContainerFormProps) {
  const compute = useCompute();
  const { toast } = useToast();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      image: '',
      command: '',
      ports: [],
      memoryMB: 512,
      cpuShares: 512,
    },
  });

  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: 'ports',
  });

  const createContainerMutation = useMutation(
    (values: FormValues) => {
      // Transform form values to SDK request format
      const config = {
        name: values.name,
        image: values.image,
        command: values.command ? values.command.split(' ') : undefined,
        ports: values.ports?.map(p => ({
          containerPort: p.container,
          hostPort: p.host,
          protocol: p.protocol,
        })),
        resources: {
          maxMemoryMb: values.memoryMB,
          maxCpus: values.cpuShares ? values.cpuShares / 1024 : undefined,
        },
      };
      return compute.createContainer({ config });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Container created successfully',
        });
        form.reset();
        onOpenChange(false);
        onSuccess();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to create container: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const onSubmit = (values: FormValues) => {
    createContainerMutation.mutate(values);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create Container</DialogTitle>
          <DialogDescription>
            Create a new container from a Docker image.
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
                    <Input placeholder="my-container" {...field} />
                  </FormControl>
                  <FormDescription>Unique name for the container</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="image"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Image</FormLabel>
                  <FormControl>
                    <Input placeholder="nginx:latest" {...field} />
                  </FormControl>
                  <FormDescription>Docker image to use</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="command"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Command (Optional)</FormLabel>
                  <FormControl>
                    <Input placeholder="Override default command" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <FormLabel>Port Mappings</FormLabel>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    append({ container: 80, host: 8080, protocol: 'tcp' })
                  }
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Add Port
                </Button>
              </div>
              {fields.map((field, index) => (
                <div key={field.id} className="flex gap-2 items-start">
                  <FormField
                    control={form.control}
                    name={`ports.${index}.host`}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormControl>
                          <Input type="number" placeholder="Host" {...numberFieldProps(field)} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`ports.${index}.container`}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormControl>
                          <Input type="number" placeholder="Container" {...numberFieldProps(field)} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`ports.${index}.protocol`}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <Select
                          onValueChange={field.onChange}
                          defaultValue={field.value}
                        >
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="tcp">TCP</SelectItem>
                            <SelectItem value="udp">UDP</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => remove(index)}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="memoryMB"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Memory (MB)</FormLabel>
                    <FormControl>
                      <Input type="number" min={128} {...numberFieldProps(field)} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="cpuShares"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>CPU Shares</FormLabel>
                    <FormControl>
                      <Input type="number" min={0} max={1024} {...numberFieldProps(field)} />
                    </FormControl>
                    <FormDescription>0-1024 (512 = normal)</FormDescription>
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
                disabled={createContainerMutation.isLoading}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createContainerMutation.isLoading}>
                {createContainerMutation.isLoading ? 'Creating...' : 'Create Container'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

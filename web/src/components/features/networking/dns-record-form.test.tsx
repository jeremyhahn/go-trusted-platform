import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DNSRecord } from '@/types/infrastructure';
import { toRecordType } from '@/utils/dns-record-type';

import { DNSRecordForm } from './dns-record-form';

// The DNS record form validates with zod and calls the DNS service through
// the hooks. The hooks are replaced with plain fakes: useMutation runs the
// mutation function and hands its result or error to the callbacks, so the
// tests see exactly what the form sends and what it does with the answer.

const addRecord = vi.fn();
const updateRecord = vi.fn();
const toast = vi.fn();

vi.mock('@/hooks', () => ({
  useDNS: () => ({ addRecord, updateRecord }),
  useToast: () => ({ toast }),
  useMutation: <V, R>(
    fn: (v: V) => Promise<R>,
    opts?: { onSuccess?: (r: R) => void; onError?: (e: Error) => void },
  ) => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const [isLoading, setLoading] = useState(false);
    return {
      isLoading,
      mutate: async (v: V) => {
        setLoading(true);
        try {
          const r = await fn(v);
          setLoading(false);
          opts?.onSuccess?.(r);
        } catch (e) {
          setLoading(false);
          opts?.onError?.(e as Error);
        }
      },
    };
  },
}));

// Radix Select does not open in jsdom; a native select carries the same
// onValueChange / defaultValue / disabled contract.
vi.mock('@/components/ui/select', () => ({
  Select: ({
    onValueChange,
    defaultValue,
    disabled,
    children,
  }: {
    onValueChange: (v: string) => void;
    defaultValue?: string;
    disabled?: boolean;
    children: ReactNode;
  }) => (
    <select
      aria-label="Type"
      defaultValue={defaultValue}
      disabled={disabled}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => (
    <option value={value}>{children}</option>
  ),
}));

function record(overrides: Partial<DNSRecord> = {}): DNSRecord {
  return {
    id: 'r1',
    name: 'www',
    type: 'A',
    value: '192.0.2.10',
    ttl: 300,
    ...overrides,
  } as DNSRecord;
}

function setup(props: { record?: DNSRecord } = {}) {
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(
    <DNSRecordForm
      zoneName="example.test"
      open
      onOpenChange={onOpenChange}
      onSuccess={onSuccess}
      record={props.record}
    />,
  );
  return { onOpenChange, onSuccess };
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function submit(name: string) {
  fireEvent.click(screen.getByRole('button', { name }));
}

// Submits the form past the browser's constraint check, so the zod schema
// is what decides.
function forceSubmit() {
  const form = screen.getByRole('button', { name: 'Create' }).closest('form');
  fireEvent.submit(form as HTMLFormElement);
}

beforeEach(() => {
  addRecord.mockReset().mockResolvedValue({ success: true });
  updateRecord.mockReset().mockResolvedValue({ success: true });
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe('DNSRecordForm (create)', () => {
  it('renders the add title, the zone name and only the common fields for an A record', () => {
    setup();
    expect(screen.getByText('Add DNS Record')).toBeTruthy();
    expect(screen.getByText('Create a new DNS record for example.test')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Create' })).toBeTruthy();
    expect(screen.queryByLabelText('Priority')).toBeNull();
    expect(screen.queryByLabelText('Weight')).toBeNull();
    expect(screen.queryByLabelText('Port')).toBeNull();
    expect((screen.getByLabelText('Type') as HTMLSelectElement).disabled).toBe(false);
    expect((screen.getByLabelText('Value') as HTMLInputElement).placeholder).toBe('192.168.1.1');
  });

  it('refuses an empty name and value and sends nothing', async () => {
    const { onSuccess } = setup();
    submit('Create');
    expect(await screen.findByText('Name is required')).toBeTruthy();
    expect(screen.getByText('Value is required')).toBeTruthy();
    expect(addRecord).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('refuses a TTL below 60 and above 86400', async () => {
    setup();
    type('Name', 'www');
    type('Value', '192.0.2.1');
    type('TTL (seconds)', '30');
    const input = screen.getByLabelText('TTL (seconds)') as HTMLInputElement;
    // The browser's own range check stops the click first...
    expect(input.validity.rangeUnderflow).toBe(true);
    submit('Create');
    // ...and the schema refuses it when the form is submitted anyway.
    forceSubmit();
    const ttl = () => input.getAttribute('aria-invalid');
    await waitFor(() => expect(ttl()).toBe('true'));
    type('TTL (seconds)', '60');
    await waitFor(() => expect(ttl()).toBe('false'));
    type('TTL (seconds)', '90000');
    expect(input.validity.rangeOverflow).toBe(true);
    forceSubmit();
    await waitFor(() => expect(ttl()).toBe('true'));
    expect(addRecord).not.toHaveBeenCalled();
  });

  it('creates an A record, toasts, closes and reports success', async () => {
    const { onOpenChange, onSuccess } = setup();
    type('Name', 'www');
    type('Value', '192.0.2.1');
    submit('Create');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(addRecord).toHaveBeenCalledWith({
      zoneName: 'example.test',
      record: {
        type: 'A',
        a: { name: 'www', value: '192.0.2.1', ttl: 3600 },
        aaaa: undefined,
        cname: undefined,
        mx: undefined,
        txt: undefined,
        ns: undefined,
        srv: undefined,
      },
    });
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'DNS record created successfully' });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it.each([
    ['AAAA', '2001:db8::1', 'aaaa'],
    ['CNAME', 'example.com', 'cname'],
    ['TXT', 'Record value', 'txt'],
    ['NS', 'Record value', 'ns'],
  ] as const)('creates a %s record under its own key', async (rrtype, placeholder, key) => {
    const { onSuccess } = setup();
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: rrtype } });
    expect((screen.getByLabelText('Value') as HTMLInputElement).placeholder).toBe(placeholder);
    type('Name', 'n');
    type('Value', 'v');
    submit('Create');
    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    const sent = addRecord.mock.calls[0][0].record;
    expect(sent.type).toBe(rrtype);
    expect(sent[key]).toEqual({ name: 'n', value: 'v', ttl: 3600 });
    expect(sent.a).toBeUndefined();
  });

  it('shows Priority for MX and sends it, defaulting to 0 when left blank', async () => {
    const { onSuccess } = setup();
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'MX' } });
    expect(screen.getByLabelText('Priority')).toBeTruthy();
    expect(screen.queryByLabelText('Weight')).toBeNull();
    expect((screen.getByLabelText('Value') as HTMLInputElement).placeholder).toBe('mail.example.com');
    type('Name', '@');
    type('Value', 'mail.example.test');
    submit('Create');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(addRecord.mock.calls[0][0].record.mx).toEqual({
      name: '@',
      value: 'mail.example.test',
      ttl: 3600,
      priority: 0,
    });
  });

  it('sends the MX priority the operator typed', async () => {
    const { onSuccess } = setup();
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'MX' } });
    type('Name', '@');
    type('Value', 'mail.example.test');
    type('Priority', '10');
    submit('Create');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(addRecord.mock.calls[0][0].record.mx.priority).toBe(10);
  });

  it('shows weight and port for SRV and sends the value as the target', async () => {
    const { onSuccess } = setup();
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'SRV' } });
    type('Name', '_sip._tcp');
    type('Value', 'sip.example.test');
    type('Priority', '5');
    type('Weight', '20');
    type('Port', '5060');
    submit('Create');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(addRecord.mock.calls[0][0].record.srv).toEqual({
      name: '_sip._tcp',
      target: 'sip.example.test',
      ttl: 3600,
      priority: 5,
      weight: 20,
      port: 5060,
    });
  });

  it('refuses an SRV port above 65535', async () => {
    setup();
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'SRV' } });
    type('Name', '_sip._tcp');
    type('Value', 'sip.example.test');
    type('Port', '70000');
    expect((screen.getByLabelText('Port') as HTMLInputElement).validity.rangeOverflow).toBe(true);
    forceSubmit();
    await waitFor(() => expect(screen.getByLabelText('Port').getAttribute('aria-invalid')).toBe('true'));
    expect(addRecord).not.toHaveBeenCalled();
  });

  it('toasts the error and stays open when the create fails', async () => {
    addRecord.mockRejectedValue(new Error('zone is read-only'));
    const { onOpenChange, onSuccess } = setup();
    type('Name', 'www');
    type('Value', '192.0.2.1');
    submit('Create');
    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to create record: zone is read-only',
      variant: 'destructive',
    });
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it('shows Saving... and disables both buttons while the create runs', async () => {
    addRecord.mockReturnValue(new Promise(() => {}));
    setup();
    type('Name', 'www');
    type('Value', '192.0.2.1');
    submit('Create');
    const saving = await screen.findByRole('button', { name: 'Saving...' });
    expect((saving as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('closes on Cancel without sending', () => {
    const { onOpenChange } = setup();
    submit('Cancel');
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(addRecord).not.toHaveBeenCalled();
  });
});

describe('DNSRecordForm (edit)', () => {
  it('fills the form from the record and locks the type', async () => {
    setup({ record: record({ type: 'MX', name: '@', value: 'mail.example.test', ttl: 600, priority: 10 }) });
    expect(screen.getByText('Edit DNS Record')).toBeTruthy();
    expect(screen.getByText('Update the DNS record for example.test')).toBeTruthy();
    await waitFor(() => expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('@'));
    expect((screen.getByLabelText('Value') as HTMLInputElement).value).toBe('mail.example.test');
    expect((screen.getByLabelText('TTL (seconds)') as HTMLInputElement).value).toBe('600');
    expect((screen.getByLabelText('Type') as HTMLSelectElement).disabled).toBe(true);
    expect(screen.getByRole('button', { name: 'Update' })).toBeTruthy();
  });

  it('sends the old record and the new one, then toasts and closes', async () => {
    const old = record();
    const { onOpenChange, onSuccess } = setup({ record: old });
    await waitFor(() => expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('www'));
    type('Value', '192.0.2.99');
    submit('Update');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(addRecord).not.toHaveBeenCalled();
    expect(updateRecord).toHaveBeenCalledTimes(1);
    const arg = updateRecord.mock.calls[0][0];
    expect(arg.zoneName).toBe('example.test');
    expect(arg.oldRecord.type).toEqual(toRecordType('A'));
    expect(arg.oldRecord.a).toEqual({ name: 'www', value: '192.0.2.10', ttl: 300 });
    expect(arg.newRecord.type).toBe('A');
    expect(arg.newRecord.a).toEqual({ name: 'www', value: '192.0.2.99', ttl: 300 });
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'DNS record updated successfully' });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('carries the old SRV fields, defaulting missing ones to 0', async () => {
    const old = record({ type: 'SRV', name: '_sip._tcp', value: 'sip.example.test', priority: 1 });
    const { onSuccess } = setup({ record: old });
    await waitFor(() => expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('_sip._tcp'));
    type('Port', '5061');
    submit('Update');
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    const arg = updateRecord.mock.calls[0][0];
    expect(arg.oldRecord.srv).toEqual({
      name: '_sip._tcp',
      target: 'sip.example.test',
      ttl: 300,
      priority: 1,
      weight: 0,
      port: 0,
    });
    expect(arg.newRecord.srv.port).toBe(5061);
  });

  it('toasts the error when the update fails', async () => {
    updateRecord.mockRejectedValue(new Error('conflict'));
    const { onSuccess } = setup({ record: record() });
    await waitFor(() => expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('www'));
    submit('Update');
    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to update record: conflict',
      variant: 'destructive',
    });
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it.each(['SOA', 'PTR'] as const)('does not load a %s record into the form', (rrtype) => {
    setup({ record: record({ type: rrtype }) });
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('');
    expect(screen.getByText('Edit DNS Record')).toBeTruthy();
  });
});

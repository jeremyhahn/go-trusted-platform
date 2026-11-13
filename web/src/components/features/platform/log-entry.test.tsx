import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { LogEntry as LogEntryType, LogLevel } from '@/types/platform';
import { LogEntry } from './log-entry';

const base: LogEntryType = {
  id: '1',
  timestamp: '2025-01-19T10:00:00Z',
  level: 'INFO',
  service: 'api-server',
  message: 'request served',
};

describe('LogEntry', () => {
  afterEach(cleanup);

  it('renders the timestamp, level, service and message', () => {
    render(<LogEntry entry={base} />);
    expect(screen.getByText(new Date(base.timestamp).toLocaleString())).toBeDefined();
    expect(screen.getByText('INFO')).toBeDefined();
    expect(screen.getByText('api-server')).toBeDefined();
    expect(screen.getByText('request served')).toBeDefined();
  });

  it.each([
    ['DEBUG', 'bg-gray-100'],
    ['INFO', 'bg-blue-100'],
    ['WARN', 'bg-yellow-100'],
    ['ERROR', 'bg-red-100'],
    ['FATAL', 'bg-red-200'],
    ['SECURITY', 'bg-purple-100'],
  ] as const)('styles the %s badge', (level, cls) => {
    render(<LogEntry entry={{ ...base, level }} />);
    expect(screen.getByText(level).className).toContain(cls);
  });

  it('falls back to the INFO style for an unknown level', () => {
    render(<LogEntry entry={{ ...base, level: 'TRACE' as LogLevel }} />);
    expect(screen.getByText('TRACE').className).toContain('bg-blue-100');
  });

  it('has no toggle when the entry has neither metadata nor a stack trace', () => {
    render(<LogEntry entry={base} />);
    expect(screen.queryByRole('button', { name: 'Toggle details' })).toBeNull();
    expect(screen.queryByText('Metadata')).toBeNull();
    expect(screen.queryByText('Stack Trace')).toBeNull();
  });

  it('shows metadata and stack trace only after the toggle is clicked', () => {
    render(
      <LogEntry
        entry={{
          ...base,
          level: 'ERROR',
          metadata: { attempt: 3, timeout: 5000 },
          stackTrace: 'Error: Connection timeout\n  at main',
        }}
      />,
    );
    const toggle = screen.getByRole('button', { name: 'Toggle details' });
    expect(screen.queryByText('Metadata')).toBeNull();

    fireEvent.click(toggle);
    expect(screen.getByText('Metadata')).toBeDefined();
    expect(screen.getByText(/"attempt": 3/)).toBeDefined();
    expect(screen.getByText('Stack Trace')).toBeDefined();
    expect(screen.getByText(/Error: Connection timeout/)).toBeDefined();

    fireEvent.click(toggle);
    expect(screen.queryByText('Metadata')).toBeNull();
  });

  it('shows only the metadata block when there is no stack trace', () => {
    render(<LogEntry entry={{ ...base, metadata: { k: 'v' } }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Toggle details' }));
    expect(screen.getByText('Metadata')).toBeDefined();
    expect(screen.queryByText('Stack Trace')).toBeNull();
  });

  it('shows only the stack trace block when there is no metadata', () => {
    render(<LogEntry entry={{ ...base, stackTrace: 'boom' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'Toggle details' }));
    expect(screen.getByText('Stack Trace')).toBeDefined();
    expect(screen.getByText('boom')).toBeDefined();
    expect(screen.queryByText('Metadata')).toBeNull();
  });

  it('treats an empty stack trace as no details', () => {
    render(<LogEntry entry={{ ...base, stackTrace: '' }} />);
    expect(screen.queryByRole('button', { name: 'Toggle details' })).toBeNull();
  });

  it('renders an invalid timestamp without throwing', () => {
    render(<LogEntry entry={{ ...base, timestamp: 'not-a-date' }} />);
    expect(screen.getByText('Invalid Date')).toBeDefined();
  });
});

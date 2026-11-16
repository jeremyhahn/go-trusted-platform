import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { LogEntry as LogEntryType } from '@/types/platform';
import { LogViewer } from './log-viewer';

function log(id: string, message: string): LogEntryType {
  return {
    id,
    timestamp: '2025-01-19T10:00:00Z',
    level: 'INFO',
    service: 'api-server',
    message,
  };
}

describe('LogViewer', () => {
  afterEach(cleanup);

  it('shows the default empty message and a zero count for no logs', () => {
    render(<LogViewer logs={[]} />);
    expect(screen.getByText('Log Entries')).toBeDefined();
    expect(screen.getByText('0 entries')).toBeDefined();
    expect(screen.getByText('No logs available')).toBeDefined();
  });

  it('shows a custom empty message', () => {
    render(<LogViewer logs={[]} emptyMessage="No logs match the filters" />);
    expect(screen.getByText('No logs match the filters')).toBeDefined();
    expect(screen.queryByText('No logs available')).toBeNull();
  });

  it('renders every entry in order with the count', () => {
    render(<LogViewer logs={[log('1', 'first'), log('2', 'second'), log('3', 'third')]} />);
    expect(screen.getByText('3 entries')).toBeDefined();
    expect(screen.queryByText('No logs available')).toBeNull();
    const messages = ['first', 'second', 'third'].map((m) => screen.getByText(m));
    expect(messages[0].compareDocumentPosition(messages[1]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(messages[1].compareDocumentPosition(messages[2]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('applies the default max height of 600px', () => {
    const { container } = render(<LogViewer logs={[]} />);
    const scroll = container.querySelector<HTMLElement>('[style*="max-height"]');
    expect(scroll?.style.maxHeight).toBe('600px');
  });

  it('applies a custom max height', () => {
    const { container } = render(<LogViewer logs={[log('1', 'a')]} maxHeight="240px" />);
    const scroll = container.querySelector<HTMLElement>('[style*="max-height"]');
    expect(scroll?.style.maxHeight).toBe('240px');
  });
});

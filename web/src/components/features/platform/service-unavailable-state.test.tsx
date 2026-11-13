import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { ServiceUnavailableState } from './service-unavailable-state';

describe('ServiceUnavailableState', () => {
  afterEach(cleanup);

  it('names the service in the title and shows the description', () => {
    render(
      <ServiceUnavailableState
        service="Compute"
        description="Compute runs on the control-plane nodes, not this edge node."
      />,
    );
    expect(screen.getByText('Compute is not available on this node')).toBeDefined();
    expect(
      screen.getByText('Compute runs on the control-plane nodes, not this edge node.'),
    ).toBeDefined();
  });

  it('hides the icon from assistive technology', () => {
    const { container } = render(<ServiceUnavailableState service="DNS" description="d" />);
    const icon = container.querySelector('svg');
    expect(icon).not.toBeNull();
    expect(icon?.getAttribute('aria-hidden')).toBe('true');
  });

  it('is an informational card, not an alert', () => {
    render(<ServiceUnavailableState service="DNS" description="d" />);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('renders an empty service name and description without throwing', () => {
    render(<ServiceUnavailableState service="" description="" />);
    expect(screen.getByText(/is not available on this node/)).toBeDefined();
  });

  it('renders markup-like input as text', () => {
    const { container } = render(
      <ServiceUnavailableState service="<b>x</b>" description="<script>y</script>" />,
    );
    expect(screen.getByText('<b>x</b> is not available on this node')).toBeDefined();
    expect(screen.getByText('<script>y</script>')).toBeDefined();
    expect(container.querySelector('b')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
  });
});

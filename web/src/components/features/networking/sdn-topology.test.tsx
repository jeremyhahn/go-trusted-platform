import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { SDNTopology } from './sdn-topology';

// The topology card draws one tile per node (icon and colour by type) and
// lists the links below; with neither nodes nor links it says so.

type Props = Parameters<typeof SDNTopology>[0];

const nodes: Props['nodes'] = [
  { id: 'n1', name: 'core-sw', type: 'switch' },
  { id: 'n2', name: 'edge-rt', type: 'router' },
  { id: 'n3', name: 'web-01', type: 'host' },
];

function tileOf(name: string): HTMLElement {
  // name span -> tile column; the first child is the coloured icon box.
  const column = screen.getByText(name).parentElement as HTMLElement;
  return column.firstElementChild as HTMLElement;
}

afterEach(() => {
  cleanup();
});

describe('SDNTopology', () => {
  it('says there is no data when there are neither nodes nor links', () => {
    render(<SDNTopology nodes={[]} links={[]} />);
    expect(screen.getByText('Network Topology')).toBeTruthy();
    expect(screen.getByText('No topology data available')).toBeTruthy();
    expect(screen.queryByText('Network Links')).toBeNull();
  });

  it('draws one tile per node with its name, type and type colour', () => {
    render(<SDNTopology nodes={nodes} links={[]} />);
    expect(screen.queryByText('No topology data available')).toBeNull();
    expect(screen.getByText('switch')).toBeTruthy();
    expect(screen.getByText('router')).toBeTruthy();
    expect(screen.getByText('host')).toBeTruthy();
    expect(tileOf('core-sw').className).toContain('bg-blue-500/10');
    expect(tileOf('edge-rt').className).toContain('bg-purple-500/10');
    expect(tileOf('web-01').className).toContain('bg-green-500/10');
  });

  it('gives each node type a distinct icon', () => {
    render(<SDNTopology nodes={nodes} links={[]} />);
    const icons = ['core-sw', 'edge-rt', 'web-01'].map((n) => {
      const svg = tileOf(n).querySelector('svg');
      expect(svg).not.toBeNull();
      return svg!.getAttribute('class');
    });
    expect(new Set(icons).size).toBe(3);
  });

  it('lists links with bandwidth when known and without it otherwise', () => {
    render(
      <SDNTopology
        nodes={nodes}
        links={[
          { source: 'core-sw', target: 'edge-rt', bandwidth: 10000 },
          { source: 'core-sw', target: 'web-01' },
          { source: 'core-sw', target: 'web-01', bandwidth: 0 },
        ]}
      />,
    );
    expect(screen.getByText('Network Links')).toBeTruthy();
    expect(screen.getByText('core-sw → edge-rt')).toBeTruthy();
    expect(screen.getByText('10000 Mbps')).toBeTruthy();
    // Duplicate links (same ends) both render: the list is keyed by index.
    const plain = screen.getAllByText('core-sw → web-01');
    expect(plain).toHaveLength(2);
    expect(screen.getAllByText(/Mbps/)).toHaveLength(1);
  });

  it('shows links without nodes and no empty-state message', () => {
    render(<SDNTopology nodes={[]} links={[{ source: 'a', target: 'b', bandwidth: 1 }]} />);
    expect(screen.queryByText('No topology data available')).toBeNull();
    expect(screen.getByText('a → b')).toBeTruthy();
    expect(screen.getByText('1 Mbps')).toBeTruthy();
  });
});

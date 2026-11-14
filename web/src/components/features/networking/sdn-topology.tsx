'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Network, Server, Router } from 'lucide-react';

interface TopologyNode {
  id: string;
  name: string;
  type: 'switch' | 'router' | 'host';
}

interface TopologyLink {
  source: string;
  target: string;
  bandwidth?: number;
}

interface SDNTopologyProps {
  nodes: TopologyNode[];
  links: TopologyLink[];
}

export function SDNTopology({ nodes, links }: SDNTopologyProps) {
  const getNodeIcon = (type: TopologyNode['type']) => {
    switch (type) {
      case 'switch':
        return <Network className="h-8 w-8" />;
      case 'router':
        return <Router className="h-8 w-8" />;
      case 'host':
        return <Server className="h-8 w-8" />;
    }
  };

  const getNodeColor = (type: TopologyNode['type']) => {
    switch (type) {
      case 'switch':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
      case 'router':
        return 'bg-purple-500/10 text-purple-500 border-purple-500/20';
      case 'host':
        return 'bg-green-500/10 text-green-500 border-green-500/20';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Network Topology</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-96 bg-muted/20 rounded-lg border border-border p-8">
          <div className="grid grid-cols-3 gap-8 h-full">
            {nodes.map((node) => (
              <div key={node.id} className="flex flex-col items-center justify-center">
                <div
                  className={`p-4 rounded-lg border ${getNodeColor(node.type)} transition-colors hover:bg-opacity-20`}
                >
                  {getNodeIcon(node.type)}
                </div>
                <span className="mt-2 text-sm font-medium">{node.name}</span>
                <span className="text-xs text-muted-foreground capitalize">
                  {node.type}
                </span>
              </div>
            ))}
          </div>
          {links.length === 0 && nodes.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center">
              <p className="text-muted-foreground">No topology data available</p>
            </div>
          )}
        </div>
        {links.length > 0 && (
          <div className="mt-4 space-y-2">
            <h4 className="text-sm font-medium">Network Links</h4>
            <div className="grid grid-cols-2 gap-2">
              {links.map((link, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-2 rounded-md bg-muted/50 text-sm"
                >
                  <span className="font-mono">
                    {link.source} → {link.target}
                  </span>
                  {link.bandwidth ? (
                    <span className="text-muted-foreground">
                      {link.bandwidth} Mbps
                    </span>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

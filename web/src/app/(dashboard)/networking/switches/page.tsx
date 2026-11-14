"use client";

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Network } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export default function SwitchesPage() {
  const router = useRouter();
  const [name, setName] = useState('');

  const open = () => {
    const trimmed = name.trim();
    if (trimmed) router.push(`/networking/switches/${encodeURIComponent(trimmed)}`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Switches</h1>
        <p className="text-muted-foreground mt-1">Open a managed switch by name to see its ports</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Open switch
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              open();
            }}
          >
            <div className="space-y-2 flex-1">
              <Label htmlFor="switch-name">Switch name</Label>
              <Input id="switch-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <Button type="submit" disabled={!name.trim()}>
              Open
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

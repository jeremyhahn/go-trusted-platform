'use client';

import { ShieldCheck, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useDNSSEC, useToast } from '@/hooks';
import { describeDnssecKeys } from '@/lib/dnssec-key';

interface DNSSECStatusCardProps {
  zoneName: string;
  onSigned?: () => void;
}

function errorMessage(err: unknown): string {
  if (err !== null && typeof err === 'object' && 'message' in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === 'string') {
      return message;
    }
  }
  return 'Unknown error';
}

/**
 * The zone's DNSSEC status (client.dns.getDNSSECStatus) and a Sign Zone
 * control (client.dns.signZone) (#2060).
 */
export function DNSSECStatusCard({ zoneName, onSigned }: DNSSECStatusCardProps) {
  const { status, isLoading, error, signZone, isSigning } = useDNSSEC(zoneName);
  const { toast } = useToast();

  const handleSign = async () => {
    try {
      await signZone();
      toast({ title: 'Zone signed', variant: 'success' });
      onSigned?.();
    } catch (err) {
      toast({ title: 'Failed to sign zone', description: errorMessage(err), variant: 'destructive' });
    }
  };

  let body: React.ReactNode;
  if (!status && isLoading) {
    body = <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />;
  } else if (!status && error) {
    body = <p className="text-sm text-destructive">{`DNSSEC status unavailable: ${error.message}`}</p>;
  } else {
    const dsRecords = status?.dsRecords ?? [];
    const notEnabled = status?.enabled === false;
    // The server sends only the DNSKEY records; derive what it leaves empty (#2165 Codex).
    const derived = describeDnssecKeys(status?.keys);
    const algorithm = status?.algorithm || derived.algorithm;
    const keySize = status?.keySize || derived.keySize;
    body = (
      <>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">Status</span>
          <Badge variant="outline">{status?.zoneSigned ? 'Signed' : 'Unsigned'}</Badge>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">DNSSEC enabled</span>
          <span>{status?.enabled ? 'Yes' : 'No'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">Algorithm</span>
          <span className="font-mono">{algorithm || '—'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">Key size</span>
          <span className="font-mono">{keySize || '—'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">Keys</span>
          <span className="font-mono">{status?.keys?.length ?? 0}</span>
        </div>
        {dsRecords.length > 0 && (
          <div className="pt-4 border-t border-border">
            <div className="text-sm text-muted-foreground">DS records</div>
            <div className="mt-2 space-y-1">
              {dsRecords.map((ds, index) => (
                <div key={index} data-testid="ds-record" className="font-mono text-xs break-all">
                  {`${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${ds.digest}`}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="pt-4">
          <Button onClick={handleSign} disabled={isSigning || notEnabled}>
            {isSigning ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="mr-2 h-4 w-4" />
            )}
            Sign Zone
          </Button>
          {notEnabled && (
            <p className="mt-2 text-sm text-muted-foreground">DNSSEC is not enabled on this server</p>
          )}
        </div>
      </>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>DNSSEC</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">{body}</CardContent>
    </Card>
  );
}

'use client';

/**
 * DeviceCard Component
 * Card for displaying device information
 */

import { Shield, Server, HardDrive, Calendar } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { Device, DeviceDetail } from '@/types/device';

interface DeviceCardProps {
  device: Device & Partial<Pick<DeviceDetail, 'lastHeartbeatAddr'>>;
}

export function DeviceCard({ device }: DeviceCardProps) {
  const getStatusColor = (status: Device['status']) => {
    const colors: Record<Device['status'], string> = {
      online: 'text-green-600',
      offline: 'text-gray-500',
      disabled: 'text-red-600',
      unknown: 'text-gray-400',
    };
    return colors[status];
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              {device.type === 'physical' ? (
                <Server className="h-5 w-5" />
              ) : (
                <HardDrive className="h-5 w-5" />
              )}
              {device.name}
            </CardTitle>
            <CardDescription className="mt-1">
              {device.serial ? `Serial: ${device.serial}` : 'No serial number'}
            </CardDescription>
          </div>
          <Badge
            variant={device.status === 'online' ? 'default' : 'secondary'}
            className={getStatusColor(device.status)}
          >
            {device.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-muted-foreground">Device Type</dt>
            <dd className="mt-1 text-sm">
              <Badge variant="outline">
                {device.type === 'physical' ? 'Physical' : 'Virtual'}
              </Badge>
            </dd>
          </div>

          {device.tpm && (
            <div>
              <dt className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                <Shield className="h-4 w-4" />
                TPM Available
              </dt>
              <dd className="mt-1 text-sm">
                <div className="flex flex-col gap-1">
                  <span>{device.tpm.manufacturer}</span>
                  <span className="text-xs text-muted-foreground">
                    Version {device.tpm.version} | Firmware {device.tpm.firmwareVersion}
                  </span>
                </div>
              </dd>
            </div>
          )}

          {device.lastSeen && (
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Last Seen</dt>
              <dd className="mt-1 text-sm">{formatDate(device.lastSeen)}</dd>
            </div>
          )}

          {device.lastHeartbeatAddr && (
            <div>
              <dt
                className="text-sm font-medium text-muted-foreground"
                title="The mTLS peer address the last heartbeat arrived from; the attestation collector dials it when platform DNS has no record"
              >
                Last heartbeat from
              </dt>
              <dd className="mt-1 text-sm font-mono" data-testid="last-heartbeat-addr">{device.lastHeartbeatAddr}</dd>
            </div>
          )}

          <div>
            <dt className="text-sm font-medium text-muted-foreground flex items-center gap-1">
              <Calendar className="h-4 w-4" />
              Registered
            </dt>
            <dd className="mt-1 text-sm">{formatDate(device.registeredAt)}</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}

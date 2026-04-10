/**
 * Platform types for system health, configuration, and logging
 */

export type ServiceStatus = 'up' | 'down' | 'degraded';
export type SystemStatus = 'healthy' | 'degraded' | 'down';
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export interface ServiceHealth {
  name: string;
  status: ServiceStatus;
  uptime: number;
  latencyMs: number;
  lastCheck: string;
  error?: string;
}

export interface ResourceUsage {
  cpu: {
    used: number;
    total: number;
  };
  memory: {
    usedMB: number;
    totalMB: number;
  };
  disk: {
    usedGB: number;
    totalGB: number;
  };
}

export interface SystemHealth {
  status: SystemStatus;
  services: ServiceHealth[];
  resources: ResourceUsage;
  activeConnections: number;
  timestamp: string;
}

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
}

export interface PlatformConfig {
  general: {
    name: string;
    timezone: string;
    locale: string;
  };
  security: {
    sessionTimeoutMinutes: number;
    mfaRequired: boolean;
    passwordPolicy: PasswordPolicy;
  };
  network: {
    apiEndpoint: string;
    tlsEnabled: boolean;
    tlsMinVersion: string;
  };
  tpm: {
    defaultPcrPolicy: number[];
    attestationIntervalMinutes: number;
  };
  ca: {
    defaultValidityDays: number;
    defaultKeyAlgorithm: string;
  };
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  service: string;
  message: string;
  metadata?: Record<string, unknown>;
  stackTrace?: string;
}

export interface LogFilters {
  level?: LogLevel[];
  service?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

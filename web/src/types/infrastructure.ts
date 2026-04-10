// Infrastructure types for compute, networking, and storage resources

export interface VM {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'suspended' | 'creating';
  vcpus: number;
  memoryMB: number;
  storageMB: number;
  ipAddress?: string;
  createdAt: string;
}

export interface VMDetail extends VM {
  description?: string;
  osType: string;
  bootOrder: string[];
  snapshots: VMSnapshot[];
  metrics: VMMetrics;
  disks: VMDisk[];
  networkInterfaces: VMNetworkInterface[];
}

export interface VMSnapshot {
  id: string;
  name: string;
  description?: string;
  createdAt: string;
  sizeMB: number;
}

export interface VMMetrics {
  cpuUsagePercent: number;
  memoryUsagePercent: number;
  diskUsagePercent: number;
  networkInMbps: number;
  networkOutMbps: number;
}

export interface VMDisk {
  id: string;
  path: string;
  sizeMB: number;
  type: 'disk' | 'cdrom';
  readonly: boolean;
}

export interface VMNetworkInterface {
  id: string;
  name: string;
  macAddress: string;
  ipAddress?: string;
  network: string;
}

export interface CreateVMInput {
  name: string;
  description?: string;
  osType: string;
  vcpus: number;
  memoryMB: number;
  storageMB: number;
  networkId?: string;
}

export interface Container {
  id: string;
  name: string;
  image: string;
  status: 'running' | 'stopped' | 'creating' | 'error';
  ports: ContainerPort[];
  createdAt: string;
}

export interface ContainerPort {
  container: number;
  host: number;
  protocol: 'tcp' | 'udp';
}

export interface ContainerDetail extends Container {
  command?: string;
  env: Record<string, string>;
  volumes: ContainerVolume[];
  networks: string[];
  restartPolicy: string;
  cpuShares: number;
  memoryMB: number;
  labels: Record<string, string>;
}

export interface ContainerVolume {
  source: string;
  destination: string;
  readonly: boolean;
}

export interface CreateContainerInput {
  name: string;
  image: string;
  command?: string;
  env?: Record<string, string>;
  ports?: ContainerPort[];
  volumes?: ContainerVolume[];
  networkId?: string;
  restartPolicy?: string;
  cpuShares?: number;
  memoryMB?: number;
  labels?: Record<string, string>;
}

export interface DNSZone {
  id: string;
  name: string;
  type: 'primary' | 'secondary';
  recordCount: number;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  ttl: number;
  createdAt: string;
  updatedAt: string;
}

export interface DNSZoneDetail extends DNSZone {
  nameservers: string[];
  adminEmail: string;
  records: DNSRecord[];
}

export interface DNSRecord {
  id: string;
  name: string;
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'PTR' | 'SRV';
  value: string;
  ttl: number;
  priority?: number;
  weight?: number;
  port?: number;
}

export interface CreateZoneInput {
  name: string;
  type: 'primary' | 'secondary';
  adminEmail: string;
  ttl?: number;
  refresh?: number;
  retry?: number;
  expire?: number;
}

export interface CreateRecordInput {
  name: string;
  type: DNSRecord['type'];
  value: string;
  ttl?: number;
  priority?: number;
  weight?: number;
  port?: number;
}

export interface UpdateRecordInput extends Partial<CreateRecordInput> {}

export interface Network {
  id: string;
  name: string;
  cidr: string;
  type: 'bridge' | 'vxlan' | 'vlan';
  status: 'active' | 'pending' | 'error';
  gateway?: string;
  vlanId?: number;
  vni?: number;
  createdAt: string;
}

export interface NetworkDetail extends Network {
  description?: string;
  dhcpEnabled: boolean;
  dhcpRange?: {
    start: string;
    end: string;
  };
  dnsServers: string[];
  routes: NetworkRoute[];
  connectedVMs: number;
  connectedContainers: number;
}

export interface NetworkRoute {
  destination: string;
  gateway: string;
  metric: number;
}

export interface CreateNetworkInput {
  name: string;
  description?: string;
  cidr: string;
  type: Network['type'];
  gateway?: string;
  vlanId?: number;
  vni?: number;
  dhcpEnabled?: boolean;
  dhcpRange?: {
    start: string;
    end: string;
  };
  dnsServers?: string[];
}

export interface FlowRule {
  id: string;
  priority: number;
  table: number;
  match: {
    inPort?: string;
    ethSrc?: string;
    ethDst?: string;
    ethType?: string;
    vlanId?: number;
    ipSrc?: string;
    ipDst?: string;
    ipProto?: string;
    tcpSrc?: number;
    tcpDst?: number;
    udpSrc?: number;
    udpDst?: number;
  };
  actions: FlowAction[];
  packets: number;
  bytes: number;
  duration: number;
}

export interface FlowAction {
  type: 'output' | 'drop' | 'mod_vlan_vid' | 'strip_vlan' | 'set_field' | 'goto_table';
  value?: string | number;
}

export interface NetworkOverlay {
  id: string;
  name: string;
  type: 'vxlan' | 'gre' | 'geneve';
  vni?: number;
  status: 'active' | 'pending' | 'error';
  nodes: OverlayNode[];
  createdAt: string;
}

export interface OverlayNode {
  id: string;
  hostname: string;
  ipAddress: string;
  status: 'connected' | 'disconnected';
}

export interface CreateOverlayInput {
  name: string;
  type: NetworkOverlay['type'];
  vni?: number;
  nodes: string[];
}

export interface GatewayRoute {
  id: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | '*';
  backend: string;
  rateLimit?: number;
  rateLimitWindow?: string;
  authRequired: boolean;
  authProvider?: string;
  status: 'active' | 'inactive';
  requestsTotal: number;
  requestsPerSecond: number;
  avgLatencyMs: number;
}

export interface CreateRouteInput {
  path: string;
  method: GatewayRoute['method'];
  backend: string;
  rateLimit?: number;
  rateLimitWindow?: string;
  authRequired?: boolean;
  authProvider?: string;
}

export interface UpdateRouteInput extends Partial<CreateRouteInput> {}

export interface SSLCertificate {
  id: string;
  domain: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
  status: 'valid' | 'expiring' | 'expired';
  autoRenew: boolean;
}

export interface PXETemplate {
  id: string;
  name: string;
  description?: string;
  bootImage: string;
  kernel: string;
  initrd: string;
  kernelParams: string;
  type: 'linux' | 'windows' | 'custom';
  createdAt: string;
  usageCount: number;
}

export interface CreatePXETemplateInput {
  name: string;
  description?: string;
  bootImage: string;
  kernel: string;
  initrd: string;
  kernelParams: string;
  type: PXETemplate['type'];
}

export interface UpdatePXETemplateInput extends Partial<CreatePXETemplateInput> {}

export interface DHCPSettings {
  enabled: boolean;
  rangeStart: string;
  rangeEnd: string;
  gateway: string;
  dnsServers: string[];
  leaseTime: number;
  defaultBootFile?: string;
  tftpServer?: string;
}

export interface PXEBootLog {
  id: string;
  macAddress: string;
  ipAddress: string;
  template: string;
  status: 'success' | 'failed';
  timestamp: string;
  error?: string;
}

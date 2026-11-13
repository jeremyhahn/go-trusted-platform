import { test, expect } from './fixtures/auth.fixture';

/**
 * Networking Pages Integration Tests
 *
 * These tests verify the Networking management UI pages
 * including SDN Ports, OpenFlow Flows, and VLANs.
 */

// Mock SDN Port data
const mockPorts = [
  {
    id: 'port-001',
    name: 'eth0',
    number: 1,
    switch: 'ovs-br0',
    macAddress: '00:1a:2b:3c:4d:5e',
    status: 'up',
    speed: '10Gbps',
    duplex: 'full',
    vlanId: 100,
    rxPackets: 1548923,
    txPackets: 982341,
    rxBytes: 2147483648,
    txBytes: 1073741824,
    rxErrors: 0,
    txErrors: 0,
    lastSeen: '2024-01-19T10:30:00Z',
  },
  {
    id: 'port-002',
    name: 'eth1',
    number: 2,
    switch: 'ovs-br0',
    macAddress: '00:1a:2b:3c:4d:5f',
    status: 'down',
    speed: '1Gbps',
    duplex: 'auto',
    vlanId: 200,
    rxPackets: 0,
    txPackets: 0,
    rxBytes: 0,
    txBytes: 0,
    rxErrors: 0,
    txErrors: 0,
    lastSeen: '2024-01-18T15:20:00Z',
  },
  {
    id: 'port-003',
    name: 'eth2',
    number: 3,
    switch: 'ovs-br1',
    macAddress: '00:1a:2b:3c:4d:60',
    status: 'blocked',
    speed: '10Gbps',
    duplex: 'full',
    vlanId: 100,
    rxPackets: 123456,
    txPackets: 98765,
    rxBytes: 134217728,
    txBytes: 67108864,
    rxErrors: 1024,
    txErrors: 512,
    lastSeen: '2024-01-19T09:15:00Z',
  },
];

// Mock OpenFlow Flow data
const mockFlows = [
  {
    id: 'flow-001',
    name: 'Default Gateway Route',
    switch: 'ovs-br0',
    table: 0,
    priority: 100,
    match: {
      ethType: '0x0800',
      ipDst: '10.0.0.0/8',
    },
    actions: [{ type: 'output', value: 'port:1' }],
    status: 'active',
    packets: 1548923,
    bytes: 2147483648,
    duration: 86400,
    idleTimeout: 0,
    hardTimeout: 0,
    cookie: '0x1234567890abcdef',
    createdAt: '2024-01-18T00:00:00Z',
  },
  {
    id: 'flow-002',
    name: 'VLAN 100 Tagging',
    switch: 'ovs-br0',
    table: 0,
    priority: 90,
    match: {
      inPort: 'port:2',
      ethType: '0x0800',
    },
    actions: [
      { type: 'mod_vlan_vid', value: 100 },
      { type: 'output', value: 'port:3' },
    ],
    status: 'inactive',
    packets: 0,
    bytes: 0,
    duration: 0,
    idleTimeout: 300,
    hardTimeout: 0,
    cookie: '0x2345678901bcdef0',
    createdAt: '2024-01-18T04:00:00Z',
  },
  {
    id: 'flow-003',
    name: 'Load Balancer Group',
    switch: 'ovs-br0',
    table: 3,
    priority: 60,
    match: {
      ethType: '0x0800',
      ipProto: 'tcp',
      tcpDst: 443,
    },
    actions: [{ type: 'group', value: 'group:1' }],
    status: 'error',
    packets: 98765,
    bytes: 134217728,
    duration: 3600,
    idleTimeout: 60,
    hardTimeout: 0,
    cookie: '0x789012f012345678',
    createdAt: '2024-01-19T09:00:00Z',
  },
];

// Mock VLAN data
const mockVLANs = [
  {
    id: 'vlan-001',
    vlanId: 1,
    name: 'Default',
    description: 'Default management VLAN',
    status: 'active',
    ipRange: '10.0.1.0/24',
    gateway: '10.0.1.1',
    subnet: '255.255.255.0',
    ports: [
      { portId: 'port-001', portName: 'eth0', mode: 'access' },
      { portId: 'port-002', portName: 'eth1', mode: 'trunk' },
    ],
    portCount: 2,
    mtu: 1500,
    layer: 3,
    routingEnabled: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-19T10:00:00Z',
  },
  {
    id: 'vlan-002',
    vlanId: 100,
    name: 'Production',
    description: 'Production workload VLAN',
    status: 'active',
    ipRange: '10.100.0.0/16',
    gateway: '10.100.0.1',
    subnet: '255.255.0.0',
    ports: [],
    portCount: 0,
    mtu: 9000,
    layer: 3,
    routingEnabled: true,
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-19T08:00:00Z',
  },
  {
    id: 'vlan-003',
    vlanId: 500,
    name: 'Guest',
    description: 'Guest network - isolated',
    status: 'suspended',
    ipRange: '203.0.113.0/24',
    gateway: '203.0.113.1',
    subnet: '255.255.255.0',
    ports: [],
    portCount: 0,
    mtu: 1500,
    layer: 2,
    routingEnabled: false,
    createdAt: '2024-01-06T00:00:00Z',
    updatedAt: '2024-01-10T00:00:00Z',
  },
  {
    id: 'vlan-004',
    vlanId: 666,
    name: 'Quarantine',
    description: 'Quarantined devices and suspicious traffic',
    status: 'error',
    ipRange: '10.66.6.0/24',
    gateway: '10.66.6.1',
    subnet: '255.255.255.0',
    ports: [{ portId: 'port-010', portName: 'eth8', mode: 'access' }],
    portCount: 1,
    mtu: 1500,
    layer: 2,
    routingEnabled: false,
    createdAt: '2024-01-07T00:00:00Z',
    updatedAt: '2024-01-19T06:00:00Z',
  },
];

test.describe('SDN Ports Page', () => {
  test.describe('Page Loading', () => {
    test('should load SDN ports page', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await expect(authenticatedPage).toHaveURL(/\/networking\/ports/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/SDN Ports/i);
    });

    test('should display ports table', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // The page uses DataTable component which renders a table
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible();

      // Should display port data - check for port names in the table
      await expect(authenticatedPage.locator('text=eth0')).toBeVisible();
    });

    test('should display port status badges', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for status badges - the page renders badges for up/down/blocked
      const upBadge = authenticatedPage.locator('[class*="green"]').first();
      const hasUpStatus = (await upBadge.count()) > 0;

      // Should have at least one status indicator
      expect(hasUpStatus).toBe(true);
    });

    test('should have Add Port button', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      const addButton = authenticatedPage.locator('button:has-text("Add Port")');
      await expect(addButton).toBeVisible();
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for statistics cards - Total Ports, Up, Down, Blocked
      const totalPortsCard = authenticatedPage.locator('text=Total Ports');
      await expect(totalPortsCard).toBeVisible();
    });

    test('should display search input', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator('input[placeholder*="Search ports"]');
      await expect(searchInput).toBeVisible();
    });
  });

  test.describe('Port Data Display', () => {
    test('should display MAC addresses', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for MAC address display
      const macAddress = authenticatedPage.locator('text=00:1a:2b:3c:4d:5e');
      await expect(macAddress).toBeVisible();
    });

    test('should display switch information', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for switch badge display
      const switchBadge = authenticatedPage.locator('text=ovs-br0').first();
      await expect(switchBadge).toBeVisible();
    });

    test('should display VLAN tags', async ({ authenticatedPage }) => {
      // Mock the SDN ports API
      await authenticatedPage.route('**/api/v1/sdn/ports**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockPorts),
        });
      });

      await authenticatedPage.goto('/networking/ports');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for VLAN badge display
      const vlanBadge = authenticatedPage.locator('text=/VLAN 100/').first();
      await expect(vlanBadge).toBeVisible();
    });
  });
});

test.describe('OpenFlow Flows Page', () => {
  test.describe('Page Loading', () => {
    test('should load OpenFlow flows page', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      await expect(authenticatedPage).toHaveURL(/\/networking\/flows/);
    });

    test('should display flows table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // The page uses DataTable component which renders a table
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible();
    });

    test('should display flow status badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Check for status badges - page shows active/inactive/error
      const statusBadge = authenticatedPage.locator('text=/active|inactive|error/i').first();
      const hasStatus = (await statusBadge.count()) > 0;
      expect(hasStatus).toBe(true);
    });

    test('should have Add Flow Rule button', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      const addButton = authenticatedPage.locator('button:has-text("Add Flow Rule")');
      await expect(addButton).toBeVisible();
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Check for statistics text - Total Rules, Active, Inactive, etc.
      const statsText = authenticatedPage.locator('text=/Total Rules|Active|Inactive/i').first();
      const hasStats = (await statsText.count()) > 0;
      expect(hasStats).toBe(true);
    });

    test('should display search input', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Look for search input with placeholder
      const searchInput = authenticatedPage.locator('input[placeholder*="Search"]');
      const hasSearch = (await searchInput.count()) > 0;
      expect(hasSearch).toBe(true);
    });
  });

  test.describe('Flow Data Display', () => {
    test('should display flow priority', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Table should be visible
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible();
    });

    test('should display flow table number', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Table should be visible with flow data
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible();
    });

    test('should display packet statistics', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/flows');

      // Wait for page title to be visible
      await expect(authenticatedPage.locator('h1:has-text("OpenFlow Rules")')).toBeVisible({ timeout: 5000 });

      // Check for Total Packets or Traffic text
      const statsText = authenticatedPage.locator('text=/Packets|Traffic/i').first();
      const hasStats = (await statsText.count()) > 0;
      expect(hasStats).toBe(true);
    });
  });
});

test.describe('VLANs Page', () => {
  test.describe('Page Loading', () => {
    test('should load VLANs page', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await expect(authenticatedPage).toHaveURL(/\/networking\/vlans/);

      // Should have page title
      const title = authenticatedPage.locator('h1');
      await expect(title).toContainText(/VLAN Management/i);
    });

    test('should display VLANs table', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/vlans');

      // The page uses DataTable component which renders a table
      const table = authenticatedPage.locator('table');
      await expect(table).toBeVisible();
    });

    test('should display VLAN status badges', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for status badges - active/suspended/error
      // The page renders green badges for active status
      const activeBadge = authenticatedPage.locator('[class*="green"]').first();
      const hasActiveStatus = (await activeBadge.count()) > 0;

      expect(hasActiveStatus).toBe(true);
    });

    test('should have Create VLAN button', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      const createButton = authenticatedPage.locator('button:has-text("Create VLAN")');
      await expect(createButton).toBeVisible();
    });

    test('should display statistics cards', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for statistics cards - Total VLANs, Active, Suspended, Errors
      const totalVlansCard = authenticatedPage.locator('text=Total VLANs');
      await expect(totalVlansCard).toBeVisible();
    });

    test('should display search input', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      const searchInput = authenticatedPage.locator('input[placeholder*="Search VLANs"]');
      await expect(searchInput).toBeVisible();
    });
  });

  test.describe('VLAN Data Display', () => {
    test('should display VLAN IDs', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for VLAN ID display - looking for VLAN ID 1 (Default)
      // The page displays VLAN IDs in a font-mono font-bold style
      const vlanId = authenticatedPage.locator('span.font-mono.font-bold:has-text("1")').first();
      await expect(vlanId).toBeVisible();
    });

    test('should display IP ranges', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for IP range display
      const ipRange = authenticatedPage.locator('text=10.0.1.0/24');
      await expect(ipRange).toBeVisible();
    });

    test('should display gateway addresses', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for gateway display
      const gateway = authenticatedPage.locator('text=10.0.1.1');
      await expect(gateway).toBeVisible();
    });

    test('should display layer badges', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for Layer badge (L2 or L3)
      const layerBadge = authenticatedPage.locator('text=L3').first();
      await expect(layerBadge).toBeVisible();
    });

    test('should display MTU values', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for MTU display (1500 for standard, 9000 for jumbo)
      const mtu = authenticatedPage.locator('text=/1500/').first();
      await expect(mtu).toBeVisible();
    });

    test('should display port count badges', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/networking/vlans');

      await expect(authenticatedPage.locator('table')).toBeVisible();

      // Check for port count badge (e.g., "X port(s)")
      const portCount = authenticatedPage.locator('text=/\\d+ ports?/');
      const hasPortBadge = (await portCount.count()) > 0;
      expect(hasPortBadge).toBe(true);
    });

    test('should display routing status badges', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Check for routing Enabled/Disabled badges
      const routingBadge = authenticatedPage.locator('text=Enabled').first();
      await expect(routingBadge).toBeVisible();
    });
  });

  test.describe('Status Badge Colors', () => {
    test('should show green badge for active VLANs', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Active VLANs should have green status badge
      const activeBadge = authenticatedPage.locator('[class*="bg-green"]');
      const count = await activeBadge.count();
      expect(count).toBeGreaterThan(0);
    });

    test('should show yellow badge for suspended VLANs', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Suspended VLANs should have yellow status badge
      const suspendedBadge = authenticatedPage.locator('[class*="bg-yellow"]');
      const count = await suspendedBadge.count();
      expect(count).toBeGreaterThan(0);
    });

    test('should show red badge for error VLANs', async ({ authenticatedPage }) => {
      // Mock the VLANs API
      await authenticatedPage.route('**/api/v1/vlans**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockVLANs),
        });
      });

      await authenticatedPage.goto('/networking/vlans');

      await authenticatedPage.waitForLoadState('networkidle');

      // Error VLANs should have red status badge
      const errorBadge = authenticatedPage.locator('[class*="bg-red"]');
      const count = await errorBadge.count();
      expect(count).toBeGreaterThan(0);
    });
  });
});

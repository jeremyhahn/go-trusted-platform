// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * UI epic #1665 coverage-matrix slice 15 (#2052, ruling 972): the gateway
 * VIP, LB/NAT64 status and perf operations are covered by the gateway page
 * and a real-server spec that visits it.
 */

const matrix = fs
  .readFileSync(path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md'), 'utf8')
  .split('\n');

const page = '`(dashboard)/networking/gateway/page.tsx`';
const V = '`real-server/gateway-vips.spec.ts`';
const F = '`real-server/gateway-perf-flows.spec.ts`';

const rows: Array<[string, string, string]> = [
  ['AddVIP', 'POST /lb/vips', V],
  ['RemoveVIP', 'DELETE /lb/vips/{protocol}/{address}/{port}', V],
  ['GetVIP', 'GET /lb/vips/{protocol}/{address}/{port}', V],
  ['ListVIPs', 'GET /lb/vips', V],
  ['SetVIPBackends', 'PUT /lb/vips/{protocol}/{address}/{port}/backends', V],
  ['GetLBStatus', 'GET /lb/status', V],
  ['GetNAT64Status', 'GET /nat64/status', V],
  ['GetPerfFlows', 'POST /perf/flows', F],
  ['GetPerfDatapath', 'GET /perf/datapath', V],
  ['GetPerfConntrack', 'GET /perf/conntrack', V],
];

describe('coverage matrix: GatewayService VIPs, status and perf', () => {
  it('lists each slice-15 operation as covered', () => {
    for (const [op, route, spec] of rows) {
      const want = `| \`GatewayService.${op}\` | \`${route}\` | ${page} | - | ${spec} | covered |`;
      expect(
        matrix.filter((line) => line === want),
        `GatewayService.${op} row`,
      ).toHaveLength(1);
    }
  });

  it('names files that exist', () => {
    for (const file of [
      'src/app/(dashboard)/networking/gateway/page.tsx',
      'e2e/real-server/gateway-vips.spec.ts',
      'e2e/real-server/gateway-perf-flows.spec.ts',
    ]) {
      expect(fs.existsSync(path.resolve(process.cwd(), file)), file).toBe(true);
    }
  });

  it('keeps no skip-on-missing-session fixture and the gateway real-server specs never skip', () => {
    // Codex round 3 on #2163: the old integration fixture skipped when no
    // admin token was set; the specs now take a server-issued session and fail.
    const fixture = path.resolve(
      process.cwd(),
      '..',
      'test',
      'integration',
      'web',
      'fixtures',
      'admin-session.fixture.ts',
    );
    expect(fs.existsSync(fixture), fixture).toBe(false);
    for (const file of [
      'e2e/real-server/gateway-vips.spec.ts',
      'e2e/real-server/gateway-perf-flows.spec.ts',
    ]) {
      const text = fs.readFileSync(path.resolve(process.cwd(), file), 'utf8');
      expect(text, file).not.toMatch(/\.skip\(/);
      expect(text, file).not.toMatch(/E2E_ADMIN_JWT/);
      expect(text, file).toContain("from './fixtures'");
    }
  });

  it('the VIP spec drives each VIP write, the VIP read and the conntrack read through its control', () => {
    // Codex round 4 on #2163: rows marked covered must be exercised, not
    // only visited. AddVIP from the form, GetVIP through Details,
    // SetVIPBackends through Save, RemoveVIP through the confirm, and
    // GetPerfConntrack through its load button; each write counted once.
    const text = fs.readFileSync(path.resolve(process.cwd(), 'e2e/real-server/gateway-vips.spec.ts'), 'utf8');
    for (const want of [
      "getByTestId('vip-add').click()",
      'vip-details-',
      'vip-save-',
      'vip-remove-confirm',
      "getByTestId('perf-conntrack-load').click()",
      "r.method() === 'POST'",
      "r.method() === 'PUT'",
      "r.method() === 'DELETE'",
      'VIPS_PATH',
      'toHaveLength(1)',
      'sdk.gateway.removeVIP(',
    ]) {
      expect(text, want).toContain(want);
    }
    expect(text).not.toContain('send nothing');
  });

  it('the VIP spec counts reads with the page retry policy', () => {
    // Codex round 5 on #2163: the page's PlatformProvider retries a retryable
    // read, so a refused read is sent 1 + maxRetries times and reaches the
    // card only after the backoff. The spec must count reads that way.
    const providers = fs.readFileSync(path.resolve(process.cwd(), 'src/app/providers.tsx'), 'utf8');
    const retries = /maxRetries:\s*(\d+)/.exec(providers)?.[1];
    const statuses = /retryableStatuses:\s*\[([^\]]*)\]/.exec(providers)?.[1];
    expect(retries, 'providers.tsx maxRetries').toBeDefined();
    expect(statuses, 'providers.tsx retryableStatuses').toBeDefined();
    const list = (statuses ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '')
      .join(', ');

    const text = fs.readFileSync(path.resolve(process.cwd(), 'e2e/real-server/gateway-vips.spec.ts'), 'utf8');
    expect(text).toContain(`const READ_RETRIES = ${retries};`);
    expect(text).toContain(`const RETRYABLE = [${list}];`);
    expect(text).toContain('expectedReads(');
    expect(text).toContain('expect.poll(');
    expect(text).not.toContain('expect(reads).toHaveLength(1)');
    expect(text).not.toContain("waitForLoadState('networkidle');\n      expect(reads)");
  });

  it('the real-server harness serves the e2e datapath and the VIP spec requires AddVIP to succeed', () => {
    // Codex round 5 on #2163: without a datapath socket platformd refuses
    // AddVIP with 503 and the row controls never ran. The harness serves an
    // in-memory datapath platformd reaches through sdn.gateway.datapath-socket.
    const read = (...p: string[]) => fs.readFileSync(path.resolve(process.cwd(), ...p), 'utf8');

    const yaml = read('e2e/real-server/platformd.test.yaml');
    const sdn = /^sdn:\n((?:[ \t#].*\n|\n)*)/m.exec(yaml)?.[1] ?? '';
    expect(sdn, 'platformd.test.yaml sdn: section').not.toBe('');
    expect(sdn).toMatch(/^ {2}gateway:\n(?: {4}.*\n)*? {4}datapath-socket: __E2E_DATAPATH_SOCKET__$/m);

    const setup = read('e2e/real-server/global-setup.ts');
    expect(setup).toContain('E2E_DATAPATH_BIN');
    expect(setup).toContain('__E2E_DATAPATH_SOCKET__');

    const makefile = read('..', 'Makefile');
    const recipe = /^web-e2e-platformd:.*\n((?:\t.*\n)*)/m.exec(makefile)?.[1] ?? '';
    expect(recipe, 'web-e2e-platformd recipe').not.toBe('');
    expect(recipe).toContain('./test/e2e/datapath');

    const spec = read('e2e/real-server/gateway-vips.spec.ts');
    const addTest = spec.slice(spec.indexOf('AddVIP'));
    expect(addTest).not.toContain('if (!addRes.ok())');
    expect(addTest).toContain('expect(addRes.status()).toBe(201)');
  });
});

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
});

// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// #2051 and #2064 (epic #1665): the GatewayService admitted-VTEP and IPAM pool
// rows and the SDNService flow and policy rows whose page and real-server spec
// exist are covered.

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const md = (p: string) => '`' + p + '`';

const gatewayPage = '(dashboard)/networking/gateway/page.tsx';
const ipamPage = '(dashboard)/networking/ipam/page.tsx';
const flowsPage = '(dashboard)/networking/flows/page.tsx';
const policiesPage = '(dashboard)/networking/policies/page.tsx';

const vtepsSpec = 'real-server/gateway-admitted-vteps.spec.ts';
const ipamSpec = 'real-server/ipam-pools.spec.ts';
const flowsSpec = 'real-server/sdn-flows.spec.ts';
const policiesSpec = 'real-server/sdn-policies.spec.ts';

// [operation, REST, Web page, Playwright spec]
const rows: Array<[string, string, string, string]> = [
  ['GatewayService.GetGatewayAdmittedVTEP', 'GET /state/{id}/admitted-vteps/{vtep}', gatewayPage, vtepsSpec],
  ['GatewayService.ListGatewayAdmittedVTEPs', 'GET /state/{id}/admitted-vteps', gatewayPage, vtepsSpec],
  ['GatewayService.CreateIPAMPool', 'POST /sdn/gateway/ipam/pools', ipamPage, ipamSpec],
  ['GatewayService.GetIPAMPool', 'GET /sdn/gateway/ipam/pools/{id}', ipamPage, ipamSpec],
  ['GatewayService.UpdateIPAMPool', 'PUT /sdn/gateway/ipam/pools/{id}', ipamPage, ipamSpec],
  ['GatewayService.DeleteIPAMPool', 'DELETE /sdn/gateway/ipam/pools/{id}', ipamPage, ipamSpec],
  ['SDNService.FlushFlows', 'POST /bridges/{name}/flows/flush', flowsPage, flowsSpec],
  ['SDNService.GetFlowStats', 'GET /bridges/{name}/flows/{flow}/stats', flowsPage, flowsSpec],
  ['SDNService.ApplyPolicy', 'POST /policies', policiesPage, policiesSpec],
  ['SDNService.GetPolicy', 'GET /policies/{id}', policiesPage, policiesSpec],
  ['SDNService.ListPolicies', 'GET /policies', policiesPage, policiesSpec],
  ['SDNService.DeletePolicy', 'DELETE /policies/{id}', policiesPage, policiesSpec],
];

describe('coverage matrix: GatewayService and SDNService rows (#2051, #2064)', () => {
  for (const [op, route, page, spec] of rows) {
    it(`lists ${op} as covered by ${spec}`, () => {
      const want = `| \`${op}\` | \`${route}\` | ${md(page)} | - | ${md(spec)} | covered |`;
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    });
  }

  it('counts the GatewayService and SDNService rows and the total in the summary', () => {
    for (const want of [
      '| GatewayService | 29 | 19 | 0 | 10 | 0 | 0 |',
      '| SDNService | 29 | 24 | 0 | 4 | 1 | 0 |',
      '| **Total** | **529** | **239** | **41** | **167** | **51** | **31** |',
    ]) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
  });

  it('marks the Gateway and SDN slice notes done', () => {
    for (const prefix of ['14. **GatewayService (1/2):', '27. **SDNService (1/2):']) {
      const found = lines.filter((l) => l.startsWith(prefix));
      expect(found, prefix).toHaveLength(1);
      expect(found[0].endsWith('(done)'), prefix).toBe(true);
    }
  });

  it('names files that exist', () => {
    for (const p of [gatewayPage, ipamPage, flowsPage, policiesPage]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'src/app', p)), p).toBe(true);
    }
    for (const s of [vtepsSpec, ipamSpec, flowsSpec, policiesSpec]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'e2e', s)), s).toBe(true);
    }
  });
});

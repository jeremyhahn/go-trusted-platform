// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const md = (p: string) => '`' + p + '`';

const provisionPage = '(dashboard)/tpm/provision/page.tsx';
const quotePage = '(dashboard)/tpm/quote/page.tsx';
const keysPage = '(dashboard)/tpm/keys/page.tsx';
const statusPage = '(dashboard)/tpm/status/page.tsx';
const gatewayPage = '(dashboard)/networking/gateway/page.tsx';
const ipamPage = '(dashboard)/networking/gateway/ipam/page.tsx';

const provisionSpec = 'real-server/tpm-provision-quote.spec.ts';
const keysSpec = 'real-server/tpm-keys.spec.ts';
const snapshotsSpec = 'real-server/gateway-snapshots.spec.ts';
const gatewaySpec = 'real-server/gateway.spec.ts';

const keysAndStatus = md(keysPage) + '<br>' + md(statusPage) + ' (read-only)';

// [operation, REST, Web page cell, Playwright spec]
const rows: Array<[string, string, string, string]> = [
  ['TPMService.Provision', 'POST /provision', md(provisionPage), provisionSpec],
  ['TPMService.Clear', 'POST /clear', md(provisionPage), provisionSpec],
  ['TPMService.GetCapabilities', 'GET /capabilities', md(provisionPage), provisionSpec],
  ['TPMService.GetPlatformAttributes', 'GET /platform', md(provisionPage), provisionSpec],
  ['TPMService.CreateEK', 'POST /ek', keysAndStatus, keysSpec],
  ['TPMService.ImportEKCertificate', 'POST /ek/certificate', md(keysPage), keysSpec],
  ['TPMService.DeleteEK', 'DELETE /ek', keysAndStatus, keysSpec],
  ['TPMService.CreateSRK', 'POST /srk', keysAndStatus, keysSpec],
  ['TPMService.DeleteSRK', 'DELETE /srk', keysAndStatus, keysSpec],
  ['TPMService.CreateAK', 'POST /ak', md(quotePage), provisionSpec],
  ['TPMService.GetAK', 'GET /ak', md(quotePage), provisionSpec],
  ['TPMService.Quote', 'POST /quote', md(quotePage), provisionSpec],
  ['TPMService.VerifyQuote', 'POST /quote/verify', md(quotePage), provisionSpec],
  ['TPMService.Certify', 'POST /certify', md(keysPage), keysSpec],
  ['TPMService.DeleteAK', 'DELETE /ak', md(keysPage), keysSpec],
  ['GatewayService.SetGatewayMode', 'POST /mode', md(gatewayPage), snapshotsSpec],
  ['GatewayService.GetGatewaySnapshot', 'GET /state/{id}', md(gatewayPage), snapshotsSpec],
  ['GatewayService.ListGatewaySnapshots', 'GET /state', md(gatewayPage), snapshotsSpec],
  ['GatewayService.ListBGPPeers', 'GET /bgp/peers', md(gatewayPage), snapshotsSpec],
  ['GatewayService.AnnouncePrefix', 'POST /bgp/prefixes', md(gatewayPage), snapshotsSpec],
  ['GatewayService.WithdrawPrefix', 'DELETE /bgp/prefixes', md(gatewayPage), snapshotsSpec],
  ['GatewayService.AllocateIP', 'POST /ipam/allocations', md(ipamPage), gatewaySpec],
  ['GatewayService.ReleaseIP', 'DELETE /ipam/allocations', md(ipamPage), gatewaySpec],
  ['GatewayService.ListAllocations', 'GET /ipam/allocations', md(ipamPage), gatewaySpec],
];

describe('coverage matrix: TPMService slice 31 and the shipped GatewayService rows', () => {
  for (const [op, route, page, spec] of rows) {
    it(`lists ${op} as covered by ${spec}`, () => {
      const want = `| \`${op}\` | \`${route}\` | ${page} | - | ${md(spec)} | covered |`;
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    });
  }

  it('names files that exist', () => {
    const pages = [provisionPage, quotePage, keysPage, statusPage, gatewayPage, ipamPage];
    for (const p of pages) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'src/app', p)), p).toBe(true);
    }
    for (const s of [provisionSpec, keysSpec, snapshotsSpec, gatewaySpec]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'e2e', s)), s).toBe(true);
    }
  });
});

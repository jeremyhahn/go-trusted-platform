// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// #2064 (epic #1665): the SDNService bridge and port rows whose page and
// real-server spec exist are covered.

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const md = (p: string) => '`' + p + '`';

const sdnPage = '(dashboard)/networking/sdn/page.tsx';
const portsPage = '(dashboard)/networking/ports/page.tsx';

const portActionsSpec = 'real-server/sdn-port-actions.spec.ts';
const bridgesSpec = 'real-server/sdn-bridges.spec.ts';

// [operation, REST, Web page, Playwright spec]
const rows: Array<[string, string, string, string]> = [
  ['SDNService.DeleteBridge', 'DELETE /bridges/{name}', sdnPage, bridgesSpec],
  ['SDNService.GetBridge', 'GET /bridges/{name}', sdnPage, bridgesSpec],
  ['SDNService.GetPort', 'GET /bridges/{name}/ports/{port}/state', portsPage, portActionsSpec],
  ['SDNService.SetPortState', 'PUT /bridges/{name}/ports/{port}/state', portsPage, portActionsSpec],
  ['SDNService.AuthenticatePort', 'POST /bridges/{name}/ports/{port}/auth', portsPage, portActionsSpec],
  ['SDNService.RevokePortAuth', 'DELETE /bridges/{name}/ports/{port}/auth', portsPage, portActionsSpec],
  ['SDNService.GetPortStats', 'GET /bridges/{name}/ports/{port}/stats', portsPage, bridgesSpec],
];

describe('coverage matrix: SDNService bridge and port rows (#2064)', () => {
  for (const [op, route, page, spec] of rows) {
    it(`lists ${op} as covered by ${spec}`, () => {
      const want = `| \`${op}\` | \`${route}\` | ${md(page)} | - | ${md(spec)} | covered |`;
      expect(lines.filter((l) => l === want), op).toHaveLength(1);
    });
  }

  it('counts the SDNService rows in the summary', () => {
    expect(lines.filter((l) => l === '| SDNService | 29 | 24 | 0 | 4 | 1 | 0 |')).toHaveLength(1);
  });

  it('names files that exist', () => {
    for (const p of [sdnPage, portsPage]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'src/app', p)), p).toBe(true);
    }
    for (const s of [portActionsSpec, bridgesSpec]) {
      expect(fs.existsSync(path.resolve(process.cwd(), 'e2e', s)), s).toBe(true);
    }
  });
});

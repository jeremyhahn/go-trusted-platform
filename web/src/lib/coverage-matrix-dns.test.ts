// @vitest-environment node
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md');
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n');

const listPage = '`(dashboard)/networking/dns/page.tsx`';
const zonePage = '`(dashboard)/networking/dns/[zone]/page.tsx`';
const realSpec = '`real-server/dns.spec.ts`';
const bothSpecs = '`networking.spec.ts`<br>`real-server/dns.spec.ts`';

const rows: Array<[string, string, string, string]> = [
  ['CreateZone', 'POST /zones', listPage, bothSpecs],
  ['DeleteZone', 'DELETE /zones/{zone}', listPage, bothSpecs],
  ['ListZones', 'GET /zones', listPage, bothSpecs],
  ['Resolve', 'GET /resolve', listPage, realSpec],
  ['Register', 'POST /register', listPage, realSpec],
  ['GetZone', 'GET /zones/{zone}', zonePage, realSpec],
  ['UpdateZone', 'PUT /zones/{zone}', zonePage + '<br>' + listPage + ' (read-only)', realSpec],
  ['AddRecord', 'POST /zones/{zone}/records', zonePage, realSpec],
  ['DeleteRecord', 'DELETE /zones/{zone}/records/{type}/{name}', zonePage, realSpec],
  ['UpdateRecord', 'PUT /zones/{zone}/records', zonePage, realSpec],
  ['ListRecords', 'GET /zones/{zone}/records', zonePage, realSpec],
  ['SignZone', 'POST /zones/{zone}/sign', zonePage, realSpec],
  ['GetDNSSECStatus', 'GET /zones/{zone}/dnssec', zonePage, realSpec],
];

describe('coverage matrix: DNSService', () => {
  it('lists each DNSService operation the DNS pages perform as covered by the real-server spec', () => {
    for (const [op, route, page, spec] of rows) {
      const want = `| \`DNSService.${op}\` | \`${route}\` | ${page} | - | ${spec} | covered |`;
      expect(lines.filter((l) => l === want), `DNSService.${op}`).toHaveLength(1);
    }
    const missing = lines.filter(
      (l) => l.startsWith('| `DNSService.') && l.trimEnd().endsWith('| missing |'),
    );
    expect(missing, 'DNSService rows still missing').toEqual([]);
  });

  it('names files that exist', () => {
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/networking/dns/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/networking/dns/[zone]/page.tsx'))).toBe(true);
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/dns.spec.ts'))).toBe(true);
  });
});

// Areas whose operation rows use another prefix than `<Area>.`; skipped by the count.
const NO_ROWS: string[] = [];

type Counts = [number, number, number, number, number, number];

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => c.trim());
}

function summaryRows(): { areas: Array<[string, Counts]>; total: Counts } {
  const start = lines.indexOf('## Status summary by area');
  expect(start, 'status summary heading').toBeGreaterThanOrEqual(0);
  const sep = lines.findIndex((l, i) => i > start && l.startsWith('|---'));
  expect(sep, 'status summary separator').toBeGreaterThan(start);
  const areas: Array<[string, Counts]> = [];
  for (let i = sep + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.startsWith('| **Total**')) {
      const t = cells(l)
        .slice(1)
        .map((c) => Number(c.replace(/\*/g, '')));
      return { areas, total: t as Counts };
    }
    const c = cells(l);
    areas.push([c[0], c.slice(1).map(Number) as Counts]);
  }
  throw new Error('no **Total** row in the status summary');
}

// The operation tables end at the summary; the audit table after it reuses the
// `<Area>.` prefix with the status in its second cell, so it is not counted.
const operationLines = lines.slice(0, lines.indexOf('## Status summary by area'));

function countRows(area: string): Counts {
  const counts: Counts = [0, 0, 0, 0, 0, 0];
  for (const l of operationLines) {
    if (!l.startsWith(`| \`${area}.`)) continue;
    const c = cells(l);
    const status = c[c.length - 1];
    counts[0]++;
    // A status may carry a reason after it (`partial: ...`, `not-UI: ...`).
    if (status.startsWith('covered')) counts[1]++;
    else if (status.startsWith('partial')) counts[2]++;
    else if (status.startsWith('missing')) counts[3]++;
    else if (status.startsWith('not-UI')) counts[4]++;
    else if (status.startsWith('blocked')) counts[5]++;
  }
  return counts;
}

describe('coverage matrix: status summary', () => {
  it('counts each area row from the operation rows', () => {
    const { areas } = summaryRows();
    expect(areas.length).toBeGreaterThan(0);
    for (const [area, want] of areas) {
      const got = countRows(area);
      if (got[0] === 0) {
        expect(NO_ROWS, `${area} has no \`${area}.\` rows`).toContain(area);
        continue;
      }
      expect(want, `${area} summary row`).toEqual(got);
    }
  });

  it('totals the area rows', () => {
    const { areas, total } = summaryRows();
    const sums: Counts = [0, 0, 0, 0, 0, 0];
    for (const [, c] of areas) c.forEach((v, i) => (sums[i] += v));
    expect(total, '**Total** row').toEqual(sums);
  });
});

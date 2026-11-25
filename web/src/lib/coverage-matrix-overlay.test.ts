// @vitest-environment node
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const matrix = fs
  .readFileSync(path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md'), 'utf8')
  .split('\n')

const page = '`(dashboard)/networking/overlays/vteps/page.tsx`'
const spec = '`real-server/overlay-vteps.spec.ts`'

const rows: Array<[string, string]> = [
  ['ListVTEPs', 'GET /vteps'],
  ['GetVTEP', 'GET /vteps/{nodeId}'],
  ['DeleteVNI', 'DELETE /vnis/{vni:[0-9]+}'],
  ['ListTunnels', 'GET /tunnels'],
  ['GetTunnelStats', 'GET /tunnels/stats'],
  ['ListRemoteMACs', 'GET /macs'],
  ['ForgetMAC', 'DELETE /macs'],
  ['GetOverlayStatus', 'GET /status'],
]

const vniPage = '`(dashboard)/networking/overlays/page.tsx`'
const vniSpec = '`real-server/overlay-vnis.spec.ts`'

const vniRows: Array<[string, string]> = [
  ['CreateVNI', 'POST /vnis'],
  ['ListVNIs', 'GET /vnis'],
]

describe('coverage matrix: OverlayService', () => {
  it('lists the vteps page operations as covered by the real-server spec', () => {
    for (const [op, route] of rows) {
      const want = `| \`OverlayService.${op}\` | \`${route}\` | ${page} | - | ${spec} | covered |`
      expect(matrix.filter((line) => line === want), op).toHaveLength(1)
    }
    const open = matrix.filter(
      (line) =>
        line.startsWith('| `OverlayService.') &&
        (line.endsWith('| partial |') || line.endsWith('| missing |')),
    )
    expect(open).toEqual([])
  })

  it('lists the VNI page operations as covered by the real-server VNI spec', () => {
    for (const [op, route] of vniRows) {
      const want = `| \`OverlayService.${op}\` | \`${route}\` | ${vniPage} | - | ${vniSpec} | covered |`
      expect(matrix.filter((line) => line === want), op).toHaveLength(1)
    }
  })

  it('counts every OverlayService row in the status summary', () => {
    // Only the OverlayService section's rows; later audit tables also name OverlayService operations.
    const section = matrix.indexOf('## OverlayService (`overlay.proto`)')
    expect(section).toBeGreaterThanOrEqual(0)
    const next = matrix.findIndex((line, i) => i > section && line.startsWith('## '))
    const opRows = matrix
      .slice(section, next === -1 ? undefined : next)
      .filter((line) => line.startsWith('| `OverlayService.'))
    const status = (line: string) => {
      const cells = line
        .split('|')
        .map((cell) => cell.trim())
        .filter(Boolean)
      return cells[cells.length - 1]
    }
    const total = opRows.length
    const covered = opRows.filter((line) => status(line) === 'covered').length
    const partial = opRows.filter((line) => status(line) === 'partial').length
    const missing = opRows.filter((line) => status(line) === 'missing').length
    expect(total).toBe(10)
    expect(covered).toBe(10)
    const want = `| OverlayService | ${total} | ${covered} | ${partial} | ${missing} | 0 | 0 |`
    expect(matrix.filter((line) => line === want)).toHaveLength(1)
  })

  it('the Total line is the sum of the area lines', () => {
    const header =
      '| Area (service) | Operations | covered | partial | missing | not-UI | blocked: integration |'
    const start = matrix.indexOf(header)
    expect(start).toBeGreaterThanOrEqual(0)
    expect(matrix[start + 1]).toMatch(/^\|---\|/)
    const end = matrix.findIndex((line, i) => i > start && line.startsWith('| **Total** |'))
    expect(end).toBeGreaterThan(start + 1)
    const cells = (line: string) =>
      line
        .split('|')
        .map((cell) => cell.trim())
        .filter(Boolean)
        .slice(1)
        .map((cell) => Number(cell.replace(/\*\*/g, '')))
    const sums = [0, 0, 0, 0, 0, 0]
    for (const line of matrix.slice(start + 2, end)) {
      const values = cells(line)
      expect(values, line).toHaveLength(6)
      values.forEach((value, i) => {
        expect(Number.isInteger(value), line).toBe(true)
        sums[i] += value
      })
    }
    expect(cells(matrix[end])).toEqual(sums)
  })

  it('lists no OverlayService operation as partial in the summary', () => {
    const lines = matrix.filter((line) => line.startsWith('| OverlayService |'))
    expect(lines).toHaveLength(1)
    const cells = lines[0]
      .split('|')
      .map((cell) => cell.trim())
      .filter(Boolean)
    expect(cells[3]).toBe('0')
    expect(cells[4]).toBe('0')
  })

  it('names files that exist', () => {
    expect(
      fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/networking/overlays/vteps/page.tsx')),
    ).toBe(true)
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/overlay-vteps.spec.ts'))).toBe(true)
    expect(fs.existsSync(path.resolve(process.cwd(), 'src/app/(dashboard)/networking/overlays/page.tsx'))).toBe(true)
    expect(fs.existsSync(path.resolve(process.cwd(), 'e2e/real-server/overlay-vnis.spec.ts'))).toBe(true)
  })
})

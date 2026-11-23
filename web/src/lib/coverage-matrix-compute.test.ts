// @vitest-environment node
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const matrixPath = path.resolve(process.cwd(), '..', 'docs', 'ui', 'coverage-matrix.md')
const lines = fs.readFileSync(matrixPath, 'utf8').split('\n')

const spec = '`real-server/compute.spec.ts`'

const coveredRows = [
  `| \`ComputeService.SuspendVM\` | \`POST /vms/{id}/suspend\` | \`(dashboard)/compute/vms/[id]/page.tsx\` | - | ${spec} | covered |`,
  `| \`ComputeService.ResumeVM\` | \`POST /vms/{id}/resume\` | \`(dashboard)/compute/vms/[id]/page.tsx\` | - | ${spec} | covered |`,
  `| \`ComputeService.GetVM\` | \`GET /vms/{id}\` | \`(dashboard)/compute/vms/[id]/page.tsx\` | - | ${spec} | covered |`,
  `| \`ComputeService.CreateSnapshot\` | \`POST /vms/{id}/snapshots\` | \`(dashboard)/compute/snapshots/page.tsx\` | - | ${spec} | covered |`,
  `| \`ComputeService.GetSnapshot\` | \`GET /vms/{id}/snapshots/{snapshotId}\` | \`(dashboard)/compute/snapshots/[snapshotId]/page.tsx\` | - | ${spec} | covered |`,
]

function lastCell(line: string): string {
  const cells = line.split('|').map((c) => c.trim())
  // A table row starts and ends with '|', so the last cell is second from the end.
  return cells[cells.length - 2]
}

describe('coverage matrix: ComputeService (1/2)', () => {
  it('lists the operations the compute pages perform as covered by the real-server spec', () => {
    for (const row of coveredRows) {
      expect(lines.filter((l) => l === row), row).toHaveLength(1)
    }
  })

  it('counts the ComputeService summary row from its operation rows', () => {
    const ops = lines.filter((l) => l.startsWith('| `ComputeService.'))
    const counts = { covered: 0, partial: 0, missing: 0, notUI: 0, blocked: 0 }
    for (const l of ops) {
      const status = lastCell(l)
      if (status === 'covered') counts.covered++
      else if (status === 'partial') counts.partial++
      else if (status === 'missing') counts.missing++
      else if (status.startsWith('not-UI')) counts.notUI++
      else if (status.startsWith('blocked')) counts.blocked++
      else throw new Error(`unknown status in: ${l}`)
    }
    const summary = lines.filter((l) => l.startsWith('| ComputeService |'))
    expect(summary).toHaveLength(1)
    expect(summary[0]).toBe('| ComputeService | 37 | 19 | 0 | 13 | 5 | 0 |')
    expect(
      `| ComputeService | ${ops.length} | ${counts.covered} | ${counts.partial} | ${counts.missing} | ${counts.notUI} | ${counts.blocked} |`,
    ).toBe(summary[0])
  })

  it('names page files that exist', () => {
    for (const page of [
      'src/app/(dashboard)/compute/vms/[id]/page.tsx',
      'src/app/(dashboard)/compute/snapshots/page.tsx',
      'src/app/(dashboard)/compute/snapshots/[snapshotId]/page.tsx',
    ]) {
      expect(fs.existsSync(path.resolve(process.cwd(), page)), page).toBe(true)
    }
  })
})

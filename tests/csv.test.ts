import { describe, expect, it } from 'vitest'
import { CSV_HEADERS, escapeCsvField, vulnerabilitiesToCsv } from '../src/lib/csv.ts'
import type { Vulnerability } from '../src/lib/types.ts'

const sample: Vulnerability = {
  id: '1',
  title: 'Default admin, still enabled',
  asset: 'router',
  cveId: 'CVE-2021-36260',
  cvss: 9.8,
  severity: 'Critical',
  status: 'Open',
  owner: 'Network',
  dueDate: '2026-11-10',
  notes: 'Replace the password.\nThen disable WAN access.',
  createdAt: '2026-11-01T00:00:00.000Z',
  updatedAt: '2026-11-02T00:00:00.000Z',
}

describe('escapeCsvField', () => {
  it('leaves plain values untouched and quotes commas, quotes and newlines', () => {
    expect(escapeCsvField('router')).toBe('router')
    expect(escapeCsvField('a, b')).toBe('"a, b"')
    expect(escapeCsvField('say "hi"')).toBe('"say ""hi"""')
    expect(escapeCsvField('line1\nline2')).toBe('"line1\nline2"')
    expect(escapeCsvField(null)).toBe('')
  })
})

describe('vulnerabilitiesToCsv', () => {
  it('writes a header row even when there are no findings', () => {
    expect(vulnerabilitiesToCsv([])).toBe(CSV_HEADERS.join(','))
  })

  it('writes a data row with escaped fields and a one-decimal CVSS score', () => {
    const csv = vulnerabilitiesToCsv([sample])
    expect(csv.startsWith(`${CSV_HEADERS.join(',')}\n`)).toBe(true)
    expect(csv).toContain('"Default admin, still enabled"')
    expect(csv).toContain('CVE-2021-36260')
    expect(csv).toContain('9.8')
    expect(csv).toContain('"Replace the password.\nThen disable WAN access."')
    expect(csv.startsWith('Title,Asset,CVE,CVSS,Severity,Status,Owner,Due date,Notes,Created,Updated')).toBe(
      true,
    )
  })
})

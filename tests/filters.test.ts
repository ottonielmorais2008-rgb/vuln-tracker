import { describe, expect, it } from 'vitest'
import { applyFilters, uniqueAssets } from '../src/lib/filters.ts'
import { countBySeverity, countByStatus } from '../src/lib/dashboard.ts'
import type { Vulnerability, VulnerabilityFilters } from '../src/lib/types.ts'

const baseFilters: VulnerabilityFilters = {
  query: '',
  severity: 'all',
  status: 'all',
  asset: 'all',
  sortKey: 'severity',
  sortDirection: 'desc',
}

function item(overrides: Partial<Vulnerability>): Vulnerability {
  return {
    id: 'x',
    title: 'Finding',
    asset: 'nas-01',
    cveId: null,
    cvss: 5,
    severity: 'Medium',
    status: 'Open',
    owner: 'Lab',
    dueDate: '2026-11-20',
    notes: '',
    createdAt: '2026-11-01T00:00:00.000Z',
    updatedAt: '2026-11-01T00:00:00.000Z',
    ...overrides,
  }
}

const items: Vulnerability[] = [
  item({
    id: '1',
    title: 'Default admin password',
    asset: 'router',
    cveId: null,
    cvss: 9.8,
    severity: 'Critical',
    status: 'Open',
    owner: 'Network',
    dueDate: '2026-11-10',
  }),
  item({
    id: '2',
    title: 'Outdated OpenSSH',
    asset: 'nas-01',
    cveId: 'CVE-2024-6387',
    cvss: 8.1,
    severity: 'High',
    status: 'In progress',
    owner: 'Storage',
    dueDate: '2026-12-01',
  }),
  item({
    id: '3',
    title: 'DNS log retention',
    asset: 'pi-hole',
    cveId: null,
    cvss: 4.3,
    severity: 'Medium',
    status: 'Mitigated',
    owner: 'DNS',
    dueDate: null,
    notes: 'Query history kept too long',
  }),
]

describe('applyFilters', () => {
  it('searches title, asset, CVE, owner and notes', () => {
    expect(applyFilters(items, { ...baseFilters, query: 'openssh' }).map((i) => i.id)).toEqual(['2'])
    expect(applyFilters(items, { ...baseFilters, query: 'pi-hole' }).map((i) => i.id)).toEqual(['3'])
    expect(applyFilters(items, { ...baseFilters, query: 'cve-2024-6387' }).map((i) => i.id)).toEqual(['2'])
    expect(applyFilters(items, { ...baseFilters, query: 'network' }).map((i) => i.id)).toEqual(['1'])
    expect(applyFilters(items, { ...baseFilters, query: 'query history' }).map((i) => i.id)).toEqual(['3'])
  })

  it('filters by severity, status and asset', () => {
    expect(applyFilters(items, { ...baseFilters, severity: 'High' }).map((i) => i.id)).toEqual(['2'])
    expect(applyFilters(items, { ...baseFilters, status: 'Mitigated' }).map((i) => i.id)).toEqual(['3'])
    expect(applyFilters(items, { ...baseFilters, asset: 'router' }).map((i) => i.id)).toEqual(['1'])
  })

  it('sorts by severity (critical first) and can reverse that order', () => {
    expect(applyFilters(items, baseFilters).map((i) => i.severity)).toEqual([
      'Critical',
      'High',
      'Medium',
    ])
    expect(
      applyFilters(items, { ...baseFilters, sortDirection: 'asc' }).map((i) => i.severity),
    ).toEqual(['Medium', 'High', 'Critical'])
  })

  it('sorts by CVSS, due date (empty last) and title', () => {
    expect(
      applyFilters(items, { ...baseFilters, sortKey: 'cvss', sortDirection: 'desc' }).map(
        (i) => i.cvss,
      ),
    ).toEqual([9.8, 8.1, 4.3])
    expect(
      applyFilters(items, { ...baseFilters, sortKey: 'dueDate', sortDirection: 'asc' }).map(
        (i) => i.id,
      ),
    ).toEqual(['1', '2', '3'])
    expect(
      applyFilters(items, { ...baseFilters, sortKey: 'title', sortDirection: 'asc' }).map(
        (i) => i.title,
      ),
    ).toEqual(['Default admin password', 'DNS log retention', 'Outdated OpenSSH'])
  })

  it('combines a search with a status filter', () => {
    expect(
      applyFilters(items, { ...baseFilters, query: 'nas', status: 'In progress' }).map((i) => i.id),
    ).toEqual(['2'])
    expect(
      applyFilters(items, { ...baseFilters, query: 'nas', status: 'Open' }).map((i) => i.id),
    ).toEqual([])
  })
})

describe('dashboard counts and assets', () => {
  it('counts items by severity and status and lists unique assets', () => {
    expect(countBySeverity(items)).toEqual({ Critical: 1, High: 1, Medium: 1, Low: 0 })
    expect(countByStatus(items)).toEqual({
      Open: 1,
      'In progress': 1,
      Mitigated: 1,
      'Accepted risk': 0,
    })
    expect(uniqueAssets(items)).toEqual(['nas-01', 'pi-hole', 'router'])
  })
})

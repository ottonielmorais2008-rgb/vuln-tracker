import { SEVERITY_RANK } from './severity.ts'
import type { SortDirection, SortKey, Vulnerability, VulnerabilityFilters } from './types.ts'

function matchesQuery(item: Vulnerability, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (!needle) return true
  const haystack = [
    item.title,
    item.asset,
    item.cveId ?? '',
    item.owner,
    item.notes,
    item.status,
    item.severity,
  ]
    .join(' ')
    .toLowerCase()
  return haystack.includes(needle)
}

function compareNullableDates(a: string | null, b: string | null): number {
  if (a === b) return 0
  if (a === null) return 1
  if (b === null) return -1
  return a.localeCompare(b, 'en', { sensitivity: 'base' })
}

function compareItems(
  a: Vulnerability,
  b: Vulnerability,
  sortKey: SortKey,
  direction: SortDirection,
): number {
  let result = 0
  switch (sortKey) {
    case 'severity':
      result = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
      break
    case 'cvss':
      result = b.cvss - a.cvss
      break
    case 'dueDate':
      result = compareNullableDates(a.dueDate, b.dueDate)
      break
    case 'title':
      result = a.title.localeCompare(b.title, 'en', { sensitivity: 'base' })
      break
    case 'asset':
      result = a.asset.localeCompare(b.asset, 'en', { sensitivity: 'base' })
      break
    case 'status':
      result = a.status.localeCompare(b.status, 'en', { sensitivity: 'base' })
      break
    case 'owner':
      result = a.owner.localeCompare(b.owner, 'en', { sensitivity: 'base' })
      break
  }
  // severity and cvss default to highest first; flip when the user asks for asc
  if (sortKey === 'severity' || sortKey === 'cvss') {
    return direction === 'desc' ? result : -result
  }
  return direction === 'asc' ? result : -result
}

export function applyFilters(
  items: Vulnerability[],
  filters: VulnerabilityFilters,
): Vulnerability[] {
  const filtered = items.filter((item) => {
    if (!matchesQuery(item, filters.query)) return false
    if (filters.severity !== 'all' && item.severity !== filters.severity) return false
    if (filters.status !== 'all' && item.status !== filters.status) return false
    if (filters.asset !== 'all' && item.asset !== filters.asset) return false
    return true
  })

  return [...filtered].sort((a, b) =>
    compareItems(a, b, filters.sortKey, filters.sortDirection),
  )
}

export function uniqueAssets(items: Vulnerability[]): string[] {
  return [...new Set(items.map((item) => item.asset))].sort((a, b) =>
    a.localeCompare(b, 'en', { sensitivity: 'base' }),
  )
}

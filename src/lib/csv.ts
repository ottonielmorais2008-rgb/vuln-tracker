import type { Vulnerability } from './types.ts'

export const CSV_HEADERS = [
  'Title',
  'Asset',
  'CVE',
  'CVSS',
  'Severity',
  'Status',
  'Owner',
  'Due date',
  'Notes',
  'Created',
  'Updated',
] as const

export function escapeCsvField(value: string | number | null): string {
  const text = value === null || value === undefined ? '' : String(value)
  if (/[",\n\r]/.test(text)) {
    return `"${text.replaceAll('"', '""')}"`
  }
  return text
}

export function vulnerabilitiesToCsv(items: Vulnerability[]): string {
  const rows = items.map((item) =>
    [
      item.title,
      item.asset,
      item.cveId,
      item.cvss.toFixed(1),
      item.severity,
      item.status,
      item.owner,
      item.dueDate,
      item.notes,
      item.createdAt,
      item.updatedAt,
    ]
      .map(escapeCsvField)
      .join(','),
  )
  return [CSV_HEADERS.join(','), ...rows].join('\n')
}

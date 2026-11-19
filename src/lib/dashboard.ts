import { isOverdue } from './dates.ts'
import { SEVERITIES } from './types.ts'
import type { Severity, Status, Vulnerability } from './types.ts'
import { STATUSES } from './types.ts'

export function countBySeverity(items: Vulnerability[]): Record<Severity, number> {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const item of items) counts[item.severity] += 1
  return counts
}

export function countByStatus(items: Vulnerability[]): Record<Status, number> {
  const counts = { Open: 0, 'In progress': 0, Mitigated: 0, 'Accepted risk': 0 }
  for (const item of items) counts[item.status] += 1
  return counts
}

export function countOverdue(items: Vulnerability[], today: string): number {
  return items.filter((item) => isOverdue(item.dueDate, item.status, today)).length
}

export function severityOrder(): readonly Severity[] {
  return SEVERITIES
}

export function statusOrder(): readonly Status[] {
  return STATUSES
}

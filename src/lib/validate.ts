import { normalizeCveId } from './cve.ts'
import { parseCvss, severityFromCvss } from './severity.ts'
import type { Status, Vulnerability, VulnerabilityInput } from './types.ts'
import { STATUSES } from './types.ts'

function requiredText(value: string, field: string, max: number): string {
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error(`${field} is required`)
  }
  if (trimmed.length > max) {
    throw new Error(`${field} must be at most ${max} characters`)
  }
  return trimmed
}

function normalizeDueDate(value: string | null | undefined): string | null {
  const trimmed = value?.trim() ?? ''
  if (!trimmed) return null
  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    throw new Error('Due date must be a valid YYYY-MM-DD date')
  }
  const [year, month, day] = trimmed.split('-').map(Number)
  const date = new Date(year, month - 1, day)
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    throw new Error('Due date must be a valid YYYY-MM-DD date')
  }
  return trimmed
}

function normalizeStatus(value: string): Status {
  if ((STATUSES as readonly string[]).includes(value)) {
    return value as Status
  }
  throw new Error('Status is not supported')
}

export function normalizeInput(input: VulnerabilityInput): VulnerabilityInput {
  return {
    title: requiredText(input.title, 'Title', 200),
    asset: requiredText(input.asset, 'Asset', 80),
    cveId: normalizeCveId(input.cveId),
    cvss: typeof input.cvss === 'number' ? parseCvss(String(input.cvss)) : parseCvss(String(input.cvss)),
    status: normalizeStatus(input.status),
    owner: requiredText(input.owner, 'Owner', 80),
    dueDate: normalizeDueDate(input.dueDate),
    notes: (input.notes ?? '').trim() === '' ? '' : requiredText(input.notes, 'Notes', 4000),
  }
}

export function buildVulnerability(
  id: string,
  input: VulnerabilityInput,
  timestamps: { createdAt: string; updatedAt: string },
): Vulnerability {
  const normalized = normalizeInput(input)
  return {
    id,
    ...normalized,
    severity: severityFromCvss(normalized.cvss),
    createdAt: timestamps.createdAt,
    updatedAt: timestamps.updatedAt,
  }
}

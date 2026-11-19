import type { Severity } from './types.ts'

export function severityFromCvss(score: number): Severity {
  if (!Number.isFinite(score) || score < 0 || score > 10) {
    throw new Error('CVSS score must be a number between 0.0 and 10.0')
  }
  if (score >= 9.0) return 'Critical'
  if (score >= 7.0) return 'High'
  if (score >= 4.0) return 'Medium'
  return 'Low'
}

export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
}

export function parseCvss(value: string): number {
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error('CVSS score is required')
  }
  const score = Number(trimmed)
  if (!Number.isFinite(score)) {
    throw new Error('CVSS score must be a number between 0.0 and 10.0')
  }
  const rounded = Math.round(score * 10) / 10
  if (rounded < 0 || rounded > 10) {
    throw new Error('CVSS score must be a number between 0.0 and 10.0')
  }
  return rounded
}

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i

export function normalizeCveId(value: string | null | undefined): string | null {
  const trimmed = value?.trim() ?? ''
  if (!trimmed) return null
  if (!CVE_PATTERN.test(trimmed)) {
    throw new Error('CVE id must match CVE-YYYY-NNNN (at least four digits at the end)')
  }
  return trimmed.toUpperCase()
}

export function isValidCveId(value: string | null | undefined): boolean {
  try {
    normalizeCveId(value)
    return true
  } catch {
    return false
  }
}

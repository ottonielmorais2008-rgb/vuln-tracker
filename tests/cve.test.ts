import { describe, expect, it } from 'vitest'
import { isValidCveId, normalizeCveId } from '../src/lib/cve.ts'

describe('normalizeCveId', () => {
  it('accepts a standard CVE id and normalizes it to uppercase', () => {
    expect(normalizeCveId('cve-2024-1234')).toBe('CVE-2024-1234')
    expect(normalizeCveId('CVE-1999-0001')).toBe('CVE-1999-0001')
  })

  it('accepts ids with more than four trailing digits', () => {
    expect(normalizeCveId('CVE-2024-12345')).toBe('CVE-2024-12345')
  })

  it('treats a blank value as optional', () => {
    expect(normalizeCveId('')).toBeNull()
    expect(normalizeCveId('   ')).toBeNull()
    expect(normalizeCveId(null)).toBeNull()
  })

  it('rejects ids that do not match CVE-YYYY-NNNN', () => {
    expect(() => normalizeCveId('CVE-24-1234')).toThrow(/CVE-YYYY-NNNN/)
    expect(() => normalizeCveId('CVE-2024-123')).toThrow(/CVE-YYYY-NNNN/)
    expect(() => normalizeCveId('2024-1234')).toThrow(/CVE-YYYY-NNNN/)
  })
})

describe('isValidCveId', () => {
  it('returns true for valid or empty values and false otherwise', () => {
    expect(isValidCveId('CVE-2021-36260')).toBe(true)
    expect(isValidCveId('')).toBe(true)
    expect(isValidCveId('nope')).toBe(false)
  })
})

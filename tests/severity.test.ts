import { describe, expect, it } from 'vitest'
import { parseCvss, severityFromCvss } from '../src/lib/severity.ts'

describe('severityFromCvss', () => {
  it('maps 0.0 and 3.9 to Low', () => {
    expect(severityFromCvss(0)).toBe('Low')
    expect(severityFromCvss(3.9)).toBe('Low')
  })

  it('maps 4.0 and 6.9 to Medium', () => {
    expect(severityFromCvss(4)).toBe('Medium')
    expect(severityFromCvss(6.9)).toBe('Medium')
  })

  it('maps 7.0 and 8.9 to High', () => {
    expect(severityFromCvss(7)).toBe('High')
    expect(severityFromCvss(8.9)).toBe('High')
  })

  it('maps 9.0 and 10.0 to Critical', () => {
    expect(severityFromCvss(9)).toBe('Critical')
    expect(severityFromCvss(10)).toBe('Critical')
  })

  it('rejects scores outside 0.0–10.0 and non-numbers', () => {
    expect(() => severityFromCvss(-0.1)).toThrow(/between 0.0 and 10.0/)
    expect(() => severityFromCvss(10.1)).toThrow(/between 0.0 and 10.0/)
    expect(() => severityFromCvss(Number.NaN)).toThrow(/between 0.0 and 10.0/)
  })
})

describe('parseCvss', () => {
  it('parses and rounds to one decimal place', () => {
    expect(parseCvss('7.15')).toBe(7.2)
    expect(parseCvss(' 8 ')).toBe(8)
  })

  it('rejects an empty or out-of-range value', () => {
    expect(() => parseCvss('')).toThrow(/required/)
    expect(() => parseCvss('11')).toThrow(/between 0.0 and 10.0/)
    expect(() => parseCvss('abc')).toThrow(/between 0.0 and 10.0/)
  })
})

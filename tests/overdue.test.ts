import { describe, expect, it } from 'vitest'
import { isOverdue, todayIso, addDaysIso } from '../src/lib/dates.ts'
import { countOverdue } from '../src/lib/dashboard.ts'
import type { Vulnerability } from '../src/lib/types.ts'

const today = '2026-11-17'

function item(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: '1',
    title: 'Test',
    asset: 'nas-01',
    cveId: null,
    cvss: 5,
    severity: 'Medium',
    status: 'Open',
    owner: 'Lab',
    dueDate: '2026-11-16',
    notes: '',
    createdAt: '2026-11-01T00:00:00.000Z',
    updatedAt: '2026-11-01T00:00:00.000Z',
    ...overrides,
  }
}

describe('isOverdue', () => {
  it('flags open and in-progress items with a past due date', () => {
    expect(isOverdue('2026-11-16', 'Open', today)).toBe(true)
    expect(isOverdue('2026-11-16', 'In progress', today)).toBe(true)
  })

  it('does not flag mitigated or accepted items, even if the date has passed', () => {
    expect(isOverdue('2026-11-16', 'Mitigated', today)).toBe(false)
    expect(isOverdue('2026-11-16', 'Accepted risk', today)).toBe(false)
  })

  it('does not flag items due today, in the future, or without a due date', () => {
    expect(isOverdue(today, 'Open', today)).toBe(false)
    expect(isOverdue('2026-11-18', 'Open', today)).toBe(false)
    expect(isOverdue(null, 'Open', today)).toBe(false)
  })
})

describe('todayIso and addDaysIso', () => {
  it('formats a local date as YYYY-MM-DD and shifts by whole days', () => {
    expect(todayIso(new Date(2026, 10, 17, 23, 30))).toBe('2026-11-17')
    expect(addDaysIso('2026-11-17', -2)).toBe('2026-11-15')
    expect(addDaysIso('2026-11-17', 14)).toBe('2026-12-01')
  })
})

describe('countOverdue', () => {
  it('counts only actionable overdue findings', () => {
    const items = [
      item({ id: 'a', dueDate: '2026-11-10', status: 'Open' }),
      item({ id: 'b', dueDate: '2026-11-10', status: 'Mitigated' }),
      item({ id: 'c', dueDate: '2026-11-20', status: 'Open' }),
    ]
    expect(countOverdue(items, today)).toBe(1)
  })
})

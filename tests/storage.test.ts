import { describe, expect, it } from 'vitest'
import { createLocalRepository, resetLocalRepository } from '../src/lib/localStore.ts'
import { buildDemoVulnerabilities } from '../src/lib/demoData.ts'
import { normalizeInput } from '../src/lib/validate.ts'
import type { Vulnerability, VulnerabilityInput } from '../src/lib/types.ts'

class MemoryStorage {
  private data = new Map<string, string>()

  getItem(key: string): string | null {
    return this.data.has(key) ? (this.data.get(key) as string) : null
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value)
  }

  removeItem(key: string): void {
    this.data.delete(key)
  }
}

const today = '2026-11-17'

function input(overrides: Partial<VulnerabilityInput> = {}): VulnerabilityInput {
  return {
    title: 'New finding',
    asset: 'nas-01',
    cveId: 'cve-2024-1234',
    cvss: 7.5,
    status: 'Open',
    owner: 'Lab',
    dueDate: '2026-12-01',
    notes: 'Check the service.',
    ...overrides,
  }
}

describe('createLocalRepository', () => {
  it('seeds demo lab hosts when storage is empty and does not overwrite later', async () => {
    const storage = new MemoryStorage()
    const repo = createLocalRepository(storage, { today })
    const first = await repo.list()
    expect(first.length).toBeGreaterThanOrEqual(6)
    expect(first.map((item) => item.asset)).toEqual(
      expect.arrayContaining(['nas-01', 'router', 'pi-hole']),
    )

    await repo.remove(first[0].id)
    const afterDelete = await repo.list()
    const again = createLocalRepository(storage, { today })
    expect((await again.list()).map((item) => item.id)).toEqual(afterDelete.map((item) => item.id))
  })

  it('creates an item, derives severity, and normalizes the CVE id', async () => {
    const repo = createLocalRepository(new MemoryStorage(), { today, seed: [] })
    const created = await repo.create(input())
    expect(created.severity).toBe('High')
    expect(created.cveId).toBe('CVE-2024-1234')
    expect(created.title).toBe('New finding')
    expect((await repo.list())[0].id).toBe(created.id)
  })

  it('updates and removes an item, and errors when the id is missing', async () => {
    const repo = createLocalRepository(new MemoryStorage(), { today, seed: [] })
    const created = await repo.create(input())
    const updated = await repo.update(created.id, input({ title: 'Patched finding', cvss: 3.1, cveId: null }))
    expect(updated.title).toBe('Patched finding')
    expect(updated.severity).toBe('Low')
    expect(updated.createdAt).toBe(created.createdAt)
    expect(updated.updatedAt >= created.updatedAt).toBe(true)

    await repo.remove(created.id)
    expect(await repo.list()).toEqual([])
    await expect(repo.update('missing', input())).rejects.toThrow(/not found/)
    await expect(repo.remove('missing')).rejects.toThrow(/not found/)
  })

  it('rejects invalid CVE ids and CVSS scores on create', async () => {
    const repo = createLocalRepository(new MemoryStorage(), { today, seed: [] })
    await expect(repo.create(input({ cveId: 'CVE-2024-12' }))).rejects.toThrow(/CVE-YYYY-NNNN/)
    await expect(repo.create(input({ cvss: 11 }))).rejects.toThrow(/between 0.0 and 10.0/)
    await expect(repo.create(input({ title: '  ' }))).rejects.toThrow(/Title is required/)
  })

  it('can restore the seeded demo data', () => {
    const storage = new MemoryStorage()
    const repo = createLocalRepository(storage, { today, seed: [] })
    const restored = resetLocalRepository(storage, { today })
    expect(restored.map((item: Vulnerability) => item.asset)).toEqual(
      expect.arrayContaining(['nas-01', 'router', 'pi-hole']),
    )
    expect(buildDemoVulnerabilities(today).some((item) => item.dueDate !== null && item.dueDate < today)).toBe(
      true,
    )
    return expect(repo.list()).resolves.toHaveLength(restored.length)
  })
})

describe('normalizeInput', () => {
  it('trims fields and treats an empty CVE or due date as null', () => {
    const normalized = normalizeInput(
      input({ title: '  Spaced  ', cveId: '  ', dueDate: '', notes: '  ' }),
    )
    expect(normalized.title).toBe('Spaced')
    expect(normalized.cveId).toBeNull()
    expect(normalized.dueDate).toBeNull()
    expect(normalized.notes).toBe('')
  })

  it('rejects an impossible calendar date', () => {
    expect(() => normalizeInput(input({ dueDate: '2026-02-31' }))).toThrow(/valid YYYY-MM-DD/)
  })
})

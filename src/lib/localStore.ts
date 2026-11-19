import { buildVulnerability } from './validate.ts'
import { buildDemoVulnerabilities } from './demoData.ts'
import { todayIso } from './dates.ts'
import type { Vulnerability, VulnerabilityInput, VulnerabilityRepository } from './types.ts'

export const LOCAL_STORAGE_KEY = 'vuln-tracker.vulnerabilities.v1'

type MemoryStorage = {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

function readItems(storage: MemoryStorage, key: string): Vulnerability[] | null {
  const raw = storage.getItem(key)
  if (raw === null) return null
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed as Vulnerability[]
  } catch {
    return []
  }
}

function writeItems(storage: MemoryStorage, key: string, items: Vulnerability[]): void {
  storage.setItem(key, JSON.stringify(items))
}

export function createLocalRepository(
  storage: MemoryStorage = globalThis.localStorage,
  options: { key?: string; seed?: Vulnerability[]; today?: string } = {},
): VulnerabilityRepository {
  const key = options.key ?? LOCAL_STORAGE_KEY
  const today = options.today ?? todayIso()
  const seed = options.seed ?? buildDemoVulnerabilities(today)

  if (readItems(storage, key) === null) {
    writeItems(storage, key, seed)
  }

  return {
    async list() {
      return readItems(storage, key) ?? []
    },

    async create(input: VulnerabilityInput) {
      const now = new Date().toISOString()
      const item = buildVulnerability(crypto.randomUUID(), input, {
        createdAt: now,
        updatedAt: now,
      })
      const items = readItems(storage, key) ?? []
      items.unshift(item)
      writeItems(storage, key, items)
      return item
    },

    async update(id: string, input: VulnerabilityInput) {
      const items = readItems(storage, key) ?? []
      const index = items.findIndex((item) => item.id === id)
      if (index === -1) {
        throw new Error('Vulnerability not found')
      }
      const updated = buildVulnerability(id, input, {
        createdAt: items[index].createdAt,
        updatedAt: new Date().toISOString(),
      })
      items[index] = updated
      writeItems(storage, key, items)
      return updated
    },

    async remove(id: string) {
      const items = readItems(storage, key) ?? []
      const next = items.filter((item) => item.id !== id)
      if (next.length === items.length) {
        throw new Error('Vulnerability not found')
      }
      writeItems(storage, key, next)
    },
  }
}

export function resetLocalRepository(
  storage: MemoryStorage = globalThis.localStorage,
  options: { key?: string; seed?: Vulnerability[]; today?: string } = {},
): Vulnerability[] {
  const key = options.key ?? LOCAL_STORAGE_KEY
  const today = options.today ?? todayIso()
  const seed = options.seed ?? buildDemoVulnerabilities(today)
  writeItems(storage, key, seed)
  return seed
}

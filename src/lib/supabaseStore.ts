import type { SupabaseClient } from '@supabase/supabase-js'
import { normalizeInput } from './validate.ts'
import { severityFromCvss } from './severity.ts'
import type { Vulnerability, VulnerabilityInput, VulnerabilityRepository } from './types.ts'

type VulnerabilityRow = {
  id: string
  title: string
  asset: string
  cve_id: string | null
  cvss: number | string
  severity: Vulnerability['severity']
  status: Vulnerability['status']
  owner: string
  due_date: string | null
  notes: string
  created_at: string
  updated_at: string
}

function fromRow(row: VulnerabilityRow): Vulnerability {
  return {
    id: row.id,
    title: row.title,
    asset: row.asset,
    cveId: row.cve_id,
    cvss: Number(row.cvss),
    severity: row.severity,
    status: row.status,
    owner: row.owner,
    dueDate: row.due_date,
    notes: row.notes ?? '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function toRow(input: VulnerabilityInput) {
  const normalized = normalizeInput(input)
  return {
    title: normalized.title,
    asset: normalized.asset,
    cve_id: normalized.cveId,
    cvss: normalized.cvss,
    severity: severityFromCvss(normalized.cvss),
    status: normalized.status,
    owner: normalized.owner,
    due_date: normalized.dueDate,
    notes: normalized.notes,
  }
}

function throwIfError(error: { message: string } | null): void {
  if (error) {
    throw new Error(error.message)
  }
}

export function createSupabaseRepository(client: SupabaseClient): VulnerabilityRepository {
  return {
    async list() {
      const { data, error } = await client
        .from('vulnerabilities')
        .select(
          'id, title, asset, cve_id, cvss, severity, status, owner, due_date, notes, created_at, updated_at',
        )
        .order('created_at', { ascending: false })
      throwIfError(error)
      return (data as VulnerabilityRow[] | null)?.map(fromRow) ?? []
    },

    async create(input: VulnerabilityInput) {
      const { data, error } = await client
        .from('vulnerabilities')
        .insert(toRow(input))
        .select(
          'id, title, asset, cve_id, cvss, severity, status, owner, due_date, notes, created_at, updated_at',
        )
        .single()
      throwIfError(error)
      return fromRow(data as VulnerabilityRow)
    },

    async update(id: string, input: VulnerabilityInput) {
      const { data, error } = await client
        .from('vulnerabilities')
        .update(toRow(input))
        .eq('id', id)
        .select(
          'id, title, asset, cve_id, cvss, severity, status, owner, due_date, notes, created_at, updated_at',
        )
        .single()
      throwIfError(error)
      if (!data) {
        throw new Error('Vulnerability not found')
      }
      return fromRow(data as VulnerabilityRow)
    },

    async remove(id: string) {
      const { data, error } = await client
        .from('vulnerabilities')
        .delete()
        .eq('id', id)
        .select('id')
      throwIfError(error)
      if (!data || data.length === 0) {
        throw new Error('Vulnerability not found')
      }
    },
  }
}

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const
export type Severity = (typeof SEVERITIES)[number]

export const STATUSES = ['Open', 'In progress', 'Mitigated', 'Accepted risk'] as const
export type Status = (typeof STATUSES)[number]

export type Vulnerability = {
  id: string
  title: string
  asset: string
  cveId: string | null
  cvss: number
  severity: Severity
  status: Status
  owner: string
  dueDate: string | null
  notes: string
  createdAt: string
  updatedAt: string
}

export type VulnerabilityInput = {
  title: string
  asset: string
  cveId: string | null
  cvss: number
  status: Status
  owner: string
  dueDate: string | null
  notes: string
}

export type VulnerabilityRepository = {
  list(): Promise<Vulnerability[]>
  create(input: VulnerabilityInput): Promise<Vulnerability>
  update(id: string, input: VulnerabilityInput): Promise<Vulnerability>
  remove(id: string): Promise<void>
}

export type SortKey =
  | 'severity'
  | 'cvss'
  | 'dueDate'
  | 'title'
  | 'asset'
  | 'status'
  | 'owner'

export type SortDirection = 'asc' | 'desc'

export type VulnerabilityFilters = {
  query: string
  severity: Severity | 'all'
  status: Status | 'all'
  asset: string | 'all'
  sortKey: SortKey
  sortDirection: SortDirection
}

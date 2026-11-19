import { useEffect, useMemo, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { AuthPanel } from './components/AuthPanel.tsx'
import { VulnForm } from './components/VulnForm.tsx'
import { vulnerabilitiesToCsv } from './lib/csv.ts'
import { countBySeverity, countByStatus, countOverdue } from './lib/dashboard.ts'
import { isOverdue, todayIso } from './lib/dates.ts'
import { applyFilters, uniqueAssets } from './lib/filters.ts'
import { createLocalRepository, resetLocalRepository } from './lib/localStore.ts'
import { isConfigured, supabase } from './lib/supabase.ts'
import { createSupabaseRepository } from './lib/supabaseStore.ts'
import { SEVERITIES, STATUSES, type SortKey, type Vulnerability, type VulnerabilityFilters, type VulnerabilityInput, type VulnerabilityRepository } from './lib/types.ts'
import { buildDemoVulnerabilities } from './lib/demoData.ts'

const defaultFilters: VulnerabilityFilters = {
  query: '',
  severity: 'all',
  status: 'all',
  asset: 'all',
  sortKey: 'severity',
  sortDirection: 'desc',
}

function repoFor(session: Session | null): VulnerabilityRepository {
  if (session && supabase) return createSupabaseRepository(supabase)
  return createLocalRepository()
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [items, setItems] = useState<Vulnerability[]>([])
  const [filters, setFilters] = useState<VulnerabilityFilters>(defaultFilters)
  const [editing, setEditing] = useState<Vulnerability | null>(null)
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [authReady, setAuthReady] = useState(!isConfigured)
  const today = todayIso()

  const signedIn = Boolean(session)
  const isAnonymous = Boolean(session?.user.is_anonymous)
  const email = session?.user.email ?? null

  async function refresh(current = session) {
    const list = await repoFor(current).list()
    setItems(list)
  }

  useEffect(() => {
    if (!supabase) {
      void refresh(null)
      return
    }
    const client = supabase
    void client.auth.getSession().then(({ data }) => {
      setSession(data.session)
      setAuthReady(true)
      void refresh(data.session).catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Could not load findings')
      })
    })
    const { data } = client.auth.onAuthStateChange((_event, next) => {
      setSession(next)
      void refresh(next).catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Could not load findings')
      })
    })
    return () => data.subscription.unsubscribe()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const visible = useMemo(() => applyFilters(items, filters), [items, filters])
  const severityCounts = useMemo(() => countBySeverity(items), [items])
  const statusCounts = useMemo(() => countByStatus(items), [items])
  const overdueCount = useMemo(() => countOverdue(items, today), [items, today])
  const assets = useMemo(() => uniqueAssets(items), [items])

  async function run(task: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await task()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
      throw err
    } finally {
      setBusy(false)
    }
  }

  async function handleSignIn(emailValue: string, password: string) {
    const client = supabase
    if (!client) return
    await run(async () => {
      const { error: authError } = await client.auth.signInWithPassword({
        email: emailValue,
        password,
      })
      if (authError) throw authError
    })
  }

  async function handleSignUp(emailValue: string, password: string) {
    const client = supabase
    if (!client) return
    await run(async () => {
      const { error: authError } = await client.auth.signUp({ email: emailValue, password })
      if (authError) throw authError
    })
  }

  async function handleGuest() {
    const client = supabase
    if (!client) return
    await run(async () => {
      const { error: authError } = await client.auth.signInAnonymously()
      if (authError) {
        throw new Error(
          'Guest cloud sign-in is not enabled on this project. Use email sign-in, or keep working in demo mode.',
        )
      }
    })
  }

  async function handleSignOut() {
    const client = supabase
    if (!client) return
    await run(async () => {
      const { error: authError } = await client.auth.signOut()
      if (authError) throw authError
    })
  }

  async function handleSave(input: VulnerabilityInput) {
    await run(async () => {
      const repo = repoFor(session)
      if (editing) await repo.update(editing.id, input)
      else await repo.create(input)
      await refresh(session)
      setAdding(false)
      setEditing(null)
    })
  }

  async function handleDelete(item: Vulnerability) {
    if (!window.confirm(`Delete “${item.title}”? This cannot be undone.`)) return
    await run(async () => {
      await repoFor(session).remove(item.id)
      await refresh(session)
      if (editing?.id === item.id) setEditing(null)
    })
  }

  async function handleLoadSample() {
    await run(async () => {
      const repo = repoFor(session)
      const seed = buildDemoVulnerabilities(today)
      for (const item of seed) {
        await repo.create({
          title: item.title,
          asset: item.asset,
          cveId: item.cveId,
          cvss: item.cvss,
          status: item.status,
          owner: item.owner,
          dueDate: item.dueDate,
          notes: item.notes,
        })
      }
      await refresh(session)
    })
  }

  function handleResetDemo() {
    if (signedIn) return
    const restored = resetLocalRepository()
    setItems(restored)
  }

  function exportCsv() {
    const csv = vulnerabilitiesToCsv(visible)
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'vulnerabilities.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  if (!authReady) {
    return (
      <main className="app">
        <p className="muted">Loading…</p>
      </main>
    )
  }

  return (
    <main className="app">
      <header className="top">
        <div>
          <p className="eyebrow">Home lab</p>
          <h1>Vulnerability Tracker</h1>
          <p className="lede">
            Record findings against lab hosts, watch severity and status at a glance, and export a CSV.
            Demo data never leaves this browser unless you sign in.
          </p>
        </div>
        <AuthPanel
          configured={isConfigured}
          email={email}
          isAnonymous={isAnonymous}
          busy={busy}
          onSignIn={handleSignIn}
          onSignUp={handleSignUp}
          onGuest={handleGuest}
          onSignOut={handleSignOut}
        />
      </header>

      {error && <p className="error">{error}</p>}

      <section className="cards" aria-label="Summary">
        {SEVERITIES.map((severity) => (
          <article key={severity} className={`card ${severity.toLowerCase()}`}>
            <div className="label">{severity}</div>
            <div className="value">{severityCounts[severity]}</div>
          </article>
        ))}
        <article className={`card${overdueCount ? ' overdue' : ''}`}>
          <div className="label">Overdue</div>
          <div className="value">{overdueCount}</div>
        </article>
      </section>

      <section className="cards" aria-label="Status">
        {STATUSES.map((status) => (
          <article key={status} className="card">
            <div className="label">{status}</div>
            <div className="value">{statusCounts[status]}</div>
          </article>
        ))}
      </section>

      {adding || editing ? (
        <VulnForm
          key={editing?.id ?? 'new'}
          initial={editing}
          onSubmit={handleSave}
          onCancel={() => {
            setAdding(false)
            setEditing(null)
          }}
          busy={busy}
        />
      ) : (
        <section className="panel">
          <div className="toolbar">
            <input
              type="search"
              placeholder="Search title, asset, CVE, owner or notes"
              value={filters.query}
              onChange={(event) => setFilters((current) => ({ ...current, query: event.target.value }))}
            />
            <select
              value={filters.severity}
              onChange={(event) =>
                setFilters((current) => ({
                  ...current,
                  severity: event.target.value as VulnerabilityFilters['severity'],
                }))
              }
            >
              <option value="all">All severities</option>
              {SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
            <select
              value={filters.status}
              onChange={(event) =>
                setFilters((current) => ({
                  ...current,
                  status: event.target.value as VulnerabilityFilters['status'],
                }))
              }
            >
              <option value="all">All statuses</option>
              {STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
            <select
              value={filters.asset}
              onChange={(event) => setFilters((current) => ({ ...current, asset: event.target.value }))}
            >
              <option value="all">All assets</option>
              {assets.map((asset) => (
                <option key={asset} value={asset}>
                  {asset}
                </option>
              ))}
            </select>
            <select
              value={`${filters.sortKey}:${filters.sortDirection}`}
              onChange={(event) => {
                const [sortKey, sortDirection] = event.target.value.split(':') as [SortKey, 'asc' | 'desc']
                setFilters((current) => ({ ...current, sortKey, sortDirection }))
              }}
            >
              <option value="severity:desc">Severity (high to low)</option>
              <option value="severity:asc">Severity (low to high)</option>
              <option value="cvss:desc">CVSS (high to low)</option>
              <option value="cvss:asc">CVSS (low to high)</option>
              <option value="dueDate:asc">Due date (soonest)</option>
              <option value="dueDate:desc">Due date (latest)</option>
              <option value="title:asc">Title (A–Z)</option>
              <option value="asset:asc">Asset (A–Z)</option>
              <option value="status:asc">Status (A–Z)</option>
              <option value="owner:asc">Owner (A–Z)</option>
            </select>
            <button type="button" className="primary" onClick={() => setAdding(true)}>
              Add finding
            </button>
            <button type="button" onClick={exportCsv} disabled={visible.length === 0}>
              Export CSV
            </button>
            {signedIn && items.length === 0 && (
              <button type="button" onClick={() => void handleLoadSample()} disabled={busy}>
                Load sample findings
              </button>
            )}
            {!signedIn && (
              <button type="button" onClick={handleResetDemo}>
                Restore demo data
              </button>
            )}
          </div>

          {visible.length === 0 ? (
            <p className="empty">No findings match the current filters.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Asset</th>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Owner</th>
                    <th>Due</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((item) => {
                    const overdue = isOverdue(item.dueDate, item.status, today)
                    return (
                      <tr key={item.id} className={overdue ? 'overdue' : undefined}>
                        <td>
                          <strong>{item.title}</strong>
                          {item.notes ? <div className="notes">{item.notes}</div> : null}
                        </td>
                        <td className="mono">{item.asset}</td>
                        <td className="mono">{item.cveId ?? <span className="muted">—</span>}</td>
                        <td className="mono">{item.cvss.toFixed(1)}</td>
                        <td>
                          <span className={`badge ${item.severity}`}>{item.severity}</span>
                        </td>
                        <td>{item.status}</td>
                        <td>{item.owner}</td>
                        <td className="mono">
                          {item.dueDate ?? <span className="muted">—</span>}
                          {overdue ? <span className="badge overdue-flag">Overdue</span> : null}
                        </td>
                        <td>
                          <div className="row-actions">
                            <button type="button" onClick={() => setEditing(item)}>
                              Edit
                            </button>
                            <button type="button" className="danger" onClick={() => void handleDelete(item)}>
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </main>
  )
}

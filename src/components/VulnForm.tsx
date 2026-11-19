import { useState, type FormEvent } from 'react'
import { STATUSES, type Vulnerability, type VulnerabilityInput } from '../lib/types.ts'
import { parseCvss, severityFromCvss } from '../lib/severity.ts'

type Props = {
  initial?: Vulnerability | null
  onSubmit(input: VulnerabilityInput): Promise<void>
  onCancel(): void
  busy: boolean
}

export function VulnForm({ initial, onSubmit, onCancel, busy }: Props) {
  const [title, setTitle] = useState(initial?.title ?? '')
  const [asset, setAsset] = useState(initial?.asset ?? '')
  const [cveId, setCveId] = useState(initial?.cveId ?? '')
  const [cvss, setCvss] = useState(initial ? initial.cvss.toFixed(1) : '')
  const [status, setStatus] = useState(initial?.status ?? 'Open')
  const [owner, setOwner] = useState(initial?.owner ?? '')
  const [dueDate, setDueDate] = useState(initial?.dueDate ?? '')
  const [notes, setNotes] = useState(initial?.notes ?? '')
  const [error, setError] = useState<string | null>(null)

  let preview: string | null = null
  try {
    if (cvss.trim()) preview = severityFromCvss(parseCvss(cvss))
  } catch {
    preview = null
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      await onSubmit({
        title,
        asset,
        cveId: cveId.trim() ? cveId : null,
        cvss: parseCvss(cvss),
        status,
        owner,
        dueDate: dueDate.trim() ? dueDate : null,
        notes,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save the finding')
    }
  }

  return (
    <form className="panel" onSubmit={(event) => void submit(event)}>
      <h2>{initial ? 'Edit finding' : 'Add finding'}</h2>
      {error && <p className="error" style={{ marginTop: '0.75rem' }}>{error}</p>}
      <div className="form-grid">
        <label className="wide">
          Title
          <input value={title} onChange={(event) => setTitle(event.target.value)} required maxLength={200} />
        </label>
        <label>
          Asset / host
          <input value={asset} onChange={(event) => setAsset(event.target.value)} required maxLength={80} placeholder="nas-01" />
        </label>
        <label>
          Owner
          <input value={owner} onChange={(event) => setOwner(event.target.value)} required maxLength={80} />
        </label>
        <label>
          CVE id (optional)
          <input className="mono" value={cveId} onChange={(event) => setCveId(event.target.value)} placeholder="CVE-2024-1234" />
        </label>
        <label>
          CVSS score
          <input
            className="mono"
            inputMode="decimal"
            value={cvss}
            onChange={(event) => setCvss(event.target.value)}
            placeholder="0.0–10.0"
            required
          />
        </label>
        <label>
          Severity (from CVSS)
          <input value={preview ?? 'Enter a score'} readOnly />
        </label>
        <label>
          Status
          <select value={status} onChange={(event) => setStatus(event.target.value as typeof status)}>
            {STATUSES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label>
          Due date
          <input type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} />
        </label>
        <label className="wide">
          Notes
          <textarea value={notes} onChange={(event) => setNotes(event.target.value)} maxLength={4000} />
        </label>
      </div>
      <div className="form-actions">
        <button type="submit" className="primary" disabled={busy}>
          {initial ? 'Save changes' : 'Add finding'}
        </button>
        <button type="button" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  )
}

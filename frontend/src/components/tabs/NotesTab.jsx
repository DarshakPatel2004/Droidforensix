import { useEffect, useState } from 'react'
import { apiFetch } from '../../api/client'

const STATUS_OPTIONS = [
  { value: 'new', label: 'New' },
  { value: 'reviewing', label: 'Reviewing' },
  { value: 'closed', label: 'Closed' },
]

// Analyst-owned status, tags and notes for one sample (GET/PUT analyst-state).
export default function NotesTab({ sampleId }) {
  const [state, setState] = useState(null)
  const [status, setStatus] = useState('new')
  const [tagsText, setTagsText] = useState('')
  const [notes, setNotes] = useState('')
  const [loadError, setLoadError] = useState(null)
  const [saveMessage, setSaveMessage] = useState(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`)
      .then((body) => {
        if (cancelled) return
        setState(body)
        setStatus(body.status)
        setTagsText(body.tags.join(', '))
        setNotes(body.notes)
      })
      .catch((e) => { if (!cancelled) setLoadError(e.message) })
    return () => { cancelled = true }
  }, [sampleId])

  const save = async (event) => {
    event.preventDefault()
    setSaving(true)
    setSaveMessage(null)
    const tags = tagsText.split(',').map((t) => t.trim()).filter(Boolean)
    try {
      const body = await apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`, {
        method: 'PUT',
        body: JSON.stringify({ status, tags, notes }),
      })
      setState(body)
      setSaveMessage('Saved')
    } catch (e) {
      setSaveMessage(`Not saved: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  if (loadError) return <div className="empty-state" role="alert">Could not load notes: {loadError}</div>
  if (!state) return <div className="empty-state" role="status">Loading notes…</div>

  return (
    <form onSubmit={save} aria-label="Analyst notes" style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 680 }}>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 13 }}>
        Status
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ minHeight: 44, padding: '8px 10px' }}>
          {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </label>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 13 }}>
        Tags (comma separated)
        <input value={tagsText} onChange={(e) => setTagsText(e.target.value)} style={{ minHeight: 44, padding: '8px 10px' }} />
      </label>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 13 }}>
        Notes
        <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={8} style={{ padding: 10 }} />
      </label>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <button type="submit" disabled={saving} style={{ minHeight: 44, padding: '10px 16px' }}>
          {saving ? 'Saving…' : 'Save notes'}
        </button>
        {saveMessage && <span role="status" style={{ fontSize: 13 }}>{saveMessage}</span>}
      </div>
      {state.updated_utc && <div style={{ fontSize: 12, color: 'var(--text-muted, #555b66)' }}>Last saved {state.updated_utc}</div>}
    </form>
  )
}

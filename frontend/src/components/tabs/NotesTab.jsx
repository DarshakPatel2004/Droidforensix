import { useEffect, useState } from 'react'
import { apiFetch } from '../../api/client'
import Panel from '../ui/Panel'
import StateMessage from '../ui/StateMessage'

const STATUS_OPTIONS = [
  { value: 'new', label: 'New' },
  { value: 'reviewing', label: 'Reviewing' },
  { value: 'closed', label: 'Closed' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'false positive', label: 'False positive' },
]

// Analyst-owned status, tags and notes for one sample (GET/PUT analyst-state).
export default function NotesTab({ sampleId }) {
  const [saved, setSaved] = useState(null)
  const [status, setStatus] = useState('new')
  const [tagsText, setTagsText] = useState('')
  const [notes, setNotes] = useState('')
  const [loadError, setLoadError] = useState(null)
  const [feedback, setFeedback] = useState(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`)
      .then((body) => {
        if (cancelled) return
        setSaved(body)
        setStatus(body.status)
        setTagsText(body.tags.join(', '))
        setNotes(body.notes)
      })
      .catch((e) => { if (!cancelled) setLoadError(e.message) })
    return () => { cancelled = true }
  }, [sampleId])

  const tags = tagsText.split(',').map((t) => t.trim()).filter(Boolean)
  const dirty = saved && (status !== saved.status || notes !== saved.notes || tags.join('|') !== saved.tags.join('|'))

  const save = async (event) => {
    event.preventDefault()
    setSaving(true)
    setFeedback(null)
    try {
      const body = await apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`, {
        method: 'PUT',
        body: JSON.stringify({ status, tags, notes }),
      })
      setSaved(body)
      setFeedback('Saved')
    } catch (e) {
      setFeedback(`Not saved: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  if (loadError) return <StateMessage tone="error" title="Could not load notes" detail={loadError} />
  if (!saved) return <StateMessage tone="pending" title="Loading notes…" />

  return (
    <Panel title="Analyst record">
      <form onSubmit={save} aria-label="Analyst notes" className="notes-form">
        <label className="notes-field">
          <span>Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <label className="notes-field">
          <span>Tags (comma separated)</span>
          <input value={tagsText} onChange={(e) => setTagsText(e.target.value)} />
        </label>
        <label className="notes-field">
          <span>Notes</span>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={10} />
        </label>
        <div className="notes-actions">
          <button type="submit" className="notes-save" disabled={saving}>
            {saving ? 'Saving…' : 'Save notes'}
          </button>
          <span role="status" className="notes-feedback">
            {dirty ? 'Unsaved changes' : feedback}
          </span>
        </div>
        {saved.updated_utc && <p className="notes-meta">Last saved {saved.updated_utc}</p>}
      </form>
    </Panel>
  )
}

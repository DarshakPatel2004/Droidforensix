import { useState } from 'react'

const SEVERITY_CLASS = { critical: 'sev-high', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }

// Sample index: filterable list. Each row shows family and verdict so triage can happen from the list.
export default function SampleList({ samples, selectedId, backendReady, onUpload, onSelect }) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const shown = needle
    ? samples.filter((s) => `${s.fileName || ''} ${s.family || ''} ${s.sha256 || ''}`.toLowerCase().includes(needle))
    : samples

  return (
    <nav className="index-rail" aria-label="Samples">
      <div className="index-rail-head">
        <span className="index-rail-title">DroidForensix</span>
        <button type="button" className="index-rail-upload" onClick={onUpload}>New upload</button>
      </div>

      <label className="index-rail-filter">
        <span className="visually-hidden">Filter samples</span>
        <input
          type="search"
          placeholder="Filter by name, family or hash"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </label>

      <ul className="index-rail-list">
        {shown.map((s) => {
          const id = s.sha256 || s.sampleId
          const selected = id === selectedId
          const family = s.family && s.family !== 'unknown' ? s.family : 'Unattributed'
          const severity = s.severity && s.severity !== 'unknown' ? s.severity : null
          return (
            <li key={id}>
              <button
                type="button"
                className={`index-rail-item${selected ? ' is-selected' : ''}`}
                aria-current={selected ? 'true' : undefined}
                onClick={() => onSelect(s)}
              >
                <span className="index-rail-row">
                  <span className="index-rail-name">{s.fileName || id?.substring(0, 12)}</span>
                  {severity && (
                    <span className={`index-rail-verdict ${SEVERITY_CLASS[severity] || ''}`}>
                      {severity}{s.risk_score != null ? ` ${s.risk_score}` : ''}
                    </span>
                  )}
                </span>
                <span className="index-rail-family">{family}</span>
              </button>
            </li>
          )
        })}
        {shown.length === 0 && <li className="index-rail-empty">No samples match.</li>}
      </ul>

      <footer className="index-rail-foot">
        <span role="status">{backendReady ? 'Backend connected' : 'Backend offline'}</span>
        <a href="https://github.com/DarshakPatel2004/DroidForensix" target="_blank" rel="noreferrer">Docs</a>
      </footer>
    </nav>
  )
}

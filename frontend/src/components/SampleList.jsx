import { useState } from 'react'

// Left column on every page: upload entry, search, and every sample. Clicking a sample opens it.
export default function SampleList({ samples, selectedId, backendReady, onUpload, onSelect }) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const shown = needle
    ? samples.filter((s) => `${s.fileName || ''} ${s.family || ''} ${s.sha256 || ''}`.toLowerCase().includes(needle))
    : samples

  return (
    <nav className="sample-list" aria-label="Samples">
      <div className="sample-list-brand">DROID<span>FORENSIX</span></div>
      <button type="button" className="sample-list-upload" onClick={onUpload}>+ Upload APK</button>
      <input
        type="search"
        className="sample-list-search"
        placeholder="Search samples"
        aria-label="Search samples"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <ul className="sample-list-items">
        {shown.map((s) => {
          const id = s.sha256 || s.sampleId
          const family = s.family && s.family !== 'unknown' ? s.family : 'no family match'
          return (
            <li key={id}>
              <button
                type="button"
                className={`sample-list-item ${id === selectedId ? 'active' : ''}`}
                aria-current={id === selectedId ? 'true' : undefined}
                onClick={() => onSelect(s)}
              >
                <span className="sample-list-name">{s.fileName || id?.substring(0, 12)}</span>
                <span className="sample-list-meta">{family}</span>
              </button>
            </li>
          )
        })}
      </ul>
      <div className="sample-list-status" role="status">
        {backendReady ? 'Scanner online' : 'Backend offline'}
      </div>
      <a className="sample-list-docs" href="https://github.com/DarshakPatel2004/DroidForensix" target="_blank" rel="noreferrer">Documentation</a>
    </nav>
  )
}

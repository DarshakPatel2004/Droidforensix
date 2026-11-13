import { useState } from 'react'

// Case index: every sample numbered, filterable. Opening one loads it into the case file.
export default function SampleList({ samples, selectedId, backendReady, onUpload, onSelect }) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const shown = needle
    ? samples.filter((s) => `${s.fileName || ''} ${s.family || ''} ${s.sha256 || ''}`.toLowerCase().includes(needle))
    : samples

  return (
    <nav className="case-index" aria-label="Samples">
      <div className="case-index-brand">
        <span className="case-index-mark">DF</span>
        <span>
          <strong>DroidForensix</strong>
          <small>Case index</small>
        </span>
      </div>

      <button type="button" className="case-index-upload" onClick={onUpload}>
        <span>New upload</span>
        <span aria-hidden="true">+</span>
      </button>

      <label className="case-index-search">
        <span className="visually-hidden">Filter samples</span>
        <input
          type="search"
          placeholder="Filter by name, family or hash"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </label>

      <ol className="case-index-items">
        {shown.map((s, i) => {
          const id = s.sha256 || s.sampleId
          const selected = id === selectedId
          return (
            <li key={id} style={{ '--i': i }}>
              <button
                type="button"
                className={`case-index-item${selected ? ' is-selected' : ''}`}
                aria-current={selected ? 'true' : undefined}
                onClick={() => onSelect(s)}
              >
                <span className="case-index-num">{String(i + 1).padStart(2, '0')}</span>
                <span className="case-index-body">
                  <span className="case-index-name">{s.fileName || id?.substring(0, 12)}</span>
                  <span className="case-index-family">{s.family && s.family !== 'unknown' ? s.family : 'unattributed'}</span>
                </span>
              </button>
            </li>
          )
        })}
      </ol>

      <footer className="case-index-foot">
        <span className={`case-index-live${backendReady ? '' : ' is-offline'}`} role="status">
          {backendReady ? 'Scanner online' : 'Backend offline'}
        </span>
        <a href="https://github.com/DarshakPatel2004/DroidForensix" target="_blank" rel="noreferrer">Docs ↗</a>
      </footer>
    </nav>
  )
}

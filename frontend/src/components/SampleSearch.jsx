import { useState, useCallback, useMemo } from 'react'
import '../styles/SampleSearch.css'

export default function SampleSearch({ onSelect, samples }) {
  const [query, setQuery] = useState('')
  // Holds the last submitted query. Results are derived from it, so a sample list that loads later still shows.
  const [submitted, setSubmitted] = useState('')
  // /api/samples takes no query parameters, so filter the list we already have.
  const doSearch = useCallback(() => setSubmitted(query.trim().toLowerCase()), [query])
  const results = useMemo(() => {
    const all = samples || []
    if (!submitted) return all
    return all.filter(s =>
      [s.sha256, s.package_name, s.family, s.name].some(v => typeof v === 'string' && v.toLowerCase().includes(submitted))
    )
  }, [samples, submitted])

  return (
    <div className="card sample-search">
      <div className="sample-search-bar">
        <input
          className="sample-search-input"
          placeholder="Search by hash, package name, or family..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doSearch()}
          aria-label="Search samples"
        />
        <button className="btn-primary sample-search-btn" onClick={doSearch}>
          Search
        </button>
      </div>
      {results.length > 0 && (
        <div className="sample-search-results">
          {results.map((s, i) => (
            <button key={s.sha256 || i} className="sample-search-row" onClick={() => onSelect?.(s)}>
              {s.sha256?.substring(0, 16) || s.sample_id?.substring(0, 16)}...
              {s.package_name && <span className="text-muted">{s.package_name}</span>}
              {s.family && <span className="text-amber">{s.family}</span>}
            </button>
          ))}
        </div>
      )}
      {query && results.length === 0 && (
        <div className="empty-state">No samples found</div>
      )}
    </div>
  )
}

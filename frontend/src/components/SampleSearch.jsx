import { useState, useCallback } from 'react'
import { apiFetch } from '../api/client'
import '../styles/SampleSearch.css'

export default function SampleSearch({ apiUrl, onSelect, samples }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(samples || [])
  const [searching, setSearching] = useState(false)

  const doSearch = useCallback(async () => {
    if (!query.trim()) {
      setResults(samples || [])
      return
    }
    setSearching(true)
    try {
      const data = await apiFetch(`${apiUrl || 'http://localhost:8000'}/api/samples?q=${encodeURIComponent(query)}&limit=20`)
      setResults(data.samples || data || [])
    } catch {
      setResults([])
    } finally {
      setSearching(false)
    }
  }, [query, samples, apiUrl])

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
        <button className="btn-primary sample-search-btn" onClick={doSearch} disabled={searching}>
          {searching ? '...' : 'Search'}
        </button>
      </div>
      {results.length > 0 && (
        <div className="sample-search-results">
          {results.map((s, i) => (
            <button key={i} className="sample-search-row" onClick={() => onSelect?.(s)}>
              {s.sha256?.substring(0, 16) || s.sample_id?.substring(0, 16)}...
              {s.package_name && <span className="text-muted">{s.package_name}</span>}
              {s.family && <span className="text-amber">{s.family}</span>}
            </button>
          ))}
        </div>
      )}
      {!searching && query && results.length === 0 && (
        <div className="empty-state">No samples found</div>
      )}
    </div>
  )
}

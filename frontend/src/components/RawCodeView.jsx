import { useState, useEffect, useMemo } from 'react'
import ClassSourceViewer from './ClassSourceViewer'
import '../styles/RawCodeView.css'

export default function RawCodeView({ sample, apiUrl }) {
  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const [classes, setClasses] = useState([])
  const [selectedClass, setSelectedClass] = useState(null)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false

    const fetchClasses = async () => {
      try {
        setLoading(true)
        setError(null)
        const res = await fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes?limit=10000`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        if (!cancelled) {
          const classList = data.classes || []
          classList.sort((a, b) => a.name.localeCompare(b.name))
          setClasses(classList)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchClasses()
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  const filtered = useMemo(() => {
    if (!search.trim()) return classes
    const q = search.toLowerCase()
    return classes.filter(c => c.name.toLowerCase().includes(q))
  }, [classes, search])

  if (!sampleId) {
    return <div className="empty-state">No sample selected.</div>
  }

  return (
    <div className="raw-code-layout">
      <div className="card raw-code-list">
        <input
          className="raw-code-search"
          placeholder="Search classes..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          aria-label="Search classes"
        />

        <div className="raw-code-count">
          {filtered.length} of {classes.length} classes
        </div>

        <div className="raw-code-rows">
          {loading && <div className="empty-state">Loading classes...</div>}
          {error && <div className="empty-state text-rose">{error}</div>}

          {!loading && !error && filtered.map((cls, i) => (
            <button
              key={i}
              className={`raw-code-row ${selectedClass === cls.name ? 'selected' : ''}`}
              onClick={() => setSelectedClass(cls.name)}
              title={cls.name}
            >
              {cls.name.split('.').pop()}
              {cls.method_count > 0 && (
                <span className="raw-code-methods">
                  ({cls.method_count}m)
                </span>
              )}
            </button>
          ))}

          {!loading && !error && filtered.length === 0 && (
            <div className="empty-state">
              {search ? 'No classes match your search.' : 'No classes found.'}
            </div>
          )}
        </div>
      </div>

      <div className="raw-code-viewer">
        {!selectedClass ? (
          <div className="card raw-code-placeholder">
            Select a class to view its decompiled source code
          </div>
        ) : (
          <ClassSourceViewer sampleId={sampleId} className={selectedClass} apiUrl={apiUrl} />
        )}
      </div>
    </div>
  )
}

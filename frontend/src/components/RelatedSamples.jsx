import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import { fetchWithCache } from '../utils/fetchWithCache'
import Panel from './ui/Panel'
import StateMessage from './ui/StateMessage'

// Similarity band: the percentage is always shown next to its word, so colour is not the only signal.
function band(sim) {
  if (sim >= 0.9) return { label: 'High', tone: 'tone-low' }
  if (sim >= 0.7) return { label: 'Medium', tone: 'tone-medium' }
  return { label: 'Low', tone: 'tone-none' }
}

// Samples whose attribution signals overlap this one. Rows are buttons, so keyboard users can open them.
export default function RelatedSamples({ sampleId, apiUrl, onSelect }) {
  const [samples, setSamples] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false
    setLoading(true)
    setError(null)
    setSamples([])
    fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`)
      .then((d) => { if (!cancelled) { setSamples(d.related_samples || []); setLoading(false) } })
      .catch((e) => { if (!cancelled) { setError(e); setLoading(false) } })
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  if (loading) return <StateMessage tone="pending" title="Loading related samples…" />
  if (error || !samples.length) return null

  return (
    <Panel title={`Related samples (${samples.length})`}>
      <ul className="related-list">
        {samples.map((rel, i) => {
          const b = band(rel.similarity ?? 0)
          const title = rel.package_name || rel.family || 'unknown'
          const subtitle = rel.family && rel.family !== rel.package_name ? rel.family : null
          return (
            <li key={rel.sample_id || i}>
              <button
                type="button"
                className="related-row"
                onClick={() => onSelect?.({ sampleId: rel.sample_id, sha256: rel.sample_id, fileName: title, status: 'analyzed' })}
                disabled={!onSelect}
              >
                <span className="related-main">
                  <span className="mono related-name">{title}</span>
                  <span className="related-sub mono">
                    {subtitle && <span>{subtitle} · </span>}
                    {rel.sample_id?.substring(0, 16) || 'unknown'}
                  </span>
                </span>
                <span className={`related-sim ${b.tone}`}>{Math.round((rel.similarity ?? 0) * 100)}% · {b.label}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </Panel>
  )
}

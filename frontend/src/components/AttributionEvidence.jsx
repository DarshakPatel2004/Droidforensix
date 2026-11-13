import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import ConfidenceBar from './ConfidenceBar'
import Panel from './ui/Panel'
import StateMessage from './ui/StateMessage'
import { fetchWithCache } from '../utils/fetchWithCache'

const DIMENSIONS = [
  { key: 'permissions_match', label: 'Permissions match' },
  { key: 'c2_overlap', label: 'C2 overlap' },
  { key: 'obfuscation_pattern', label: 'Obfuscation pattern' },
  { key: 'code_similarity', label: 'Code similarity' },
]

// Attribution evidence: the family call, how each dimension contributed, and the signals behind it.
export default function AttributionEvidence({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false
    setLoading(true)
    setError(null)
    setData(null)
    fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`)
      .then((d) => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch((e) => { if (!cancelled) { setError(e); setLoading(false) } })
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  if (loading) return <StateMessage tone="pending" title="Loading attribution evidence…" />
  if (error) return <StateMessage tone="error" title="Attribution failed to load" detail={error.message || String(error)} />
  if (!data) return null

  const breakdown = data.confidence_breakdown || {}
  const signals = Array.isArray(data.supporting_signals) ? data.supporting_signals : []
  const codeRefs = data.code_references || null
  const hasFamily = data.family && data.family !== 'unknown'
  const confidence = typeof data.confidence === 'number' ? data.confidence : null

  return (
    <div className="attr">
      <Panel title="Family call">
        <div className="attr-call">
          <span className="attr-family">{hasFamily ? data.family : 'No family match'}</span>
          {confidence != null && hasFamily && (
            <span className="attr-confidence">{Math.round(confidence * 100)}% confidence</span>
          )}
        </div>
        {!hasFamily && <p className="attr-note">No family baseline matched this sample.</p>}
      </Panel>

      <Panel title="How the call was reached">
        <div className="attr-bars">
          {DIMENSIONS.map((dim) => (
            <ConfidenceBar key={dim.key} value={breakdown[dim.key] ?? 0} label={dim.label} />
          ))}
        </div>
      </Panel>

      {signals.length > 0 && (
        <Panel title="Supporting signals">
          <ul className="attr-list">
            {signals.map((signal, i) => <li key={i}>{signal}</li>)}
          </ul>
        </Panel>
      )}


      {codeRefs && codeRefs.total_strings > 0 && (
        <Panel title={`Code references and strings (${codeRefs.total_strings})`}>
          {Object.keys(codeRefs.by_category || {}).length > 0 && (
            <div className="attr-categories">
              {Object.entries(codeRefs.by_category).map(([cat, count]) => (
                <span key={cat}>{cat.replace(/_/g, ' ')}: <b>{count}</b></span>
              ))}
            </div>
          )}
          {codeRefs.notable_strings?.length > 0 && (
            <ul className="attr-strings">
              {codeRefs.notable_strings.map((s, i) => (
                <li key={i}>
                  <span className={`attr-entropy ${s.entropy >= 6.5 ? 'tone-high' : s.entropy >= 4 ? 'tone-medium' : 'tone-low'}`}>{s.entropy.toFixed(1)}</span>
                  <span className="mono attr-string">&quot;{s.value}&quot;</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  )
}

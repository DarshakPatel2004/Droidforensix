import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import { fetchWithCache } from '../utils/fetchWithCache'

const SIMILARITY_COLORS = [
  { min: 0.9, color: '#10b981', bg: 'rgba(16,185,129,0.1)', label: 'High' },
  { min: 0.7, color: '#06b6d4', bg: 'rgba(6,182,212,0.1)', label: 'Medium' },
  { min: 0, color: '#64748b', bg: 'rgba(100,116,139,0.1)', label: 'Low' },
]

function getSimilarityStyle(sim) {
  return SIMILARITY_COLORS.find(s => sim >= s.min) || SIMILARITY_COLORS[SIMILARITY_COLORS.length - 1]
}

export default function RelatedSamples({ sampleId, apiUrl, onSelect }) {
  const [samples, setSamples] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    setLoading(true)
    fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`)
      .then(d => { setSamples(d.related_samples || []); setLoading(false) })
      .catch(e => { setError(e); setLoading(false) })
  }, [sampleId, apiUrl])

  if (loading) return <div className="card" style={{ padding: 16, color: 'var(--text-muted)' }}>Loading related samples...</div>
  if (error) return null
  if (!samples.length) return null

  return (
    <div className="card animate-fade-in">
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 13, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
          Related Samples
        </div>
      </div>
      <div style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {samples.map((rel, i) => {
            const style = getSimilarityStyle(rel.similarity)
            const title = rel.package_name || rel.family || 'unknown'
            const subtitle = rel.family && rel.family !== rel.package_name ? rel.family : null
            return (
              <div
                key={i}
                onClick={() => onSelect?.(rel.sample_id)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '12px 16px', borderRadius: 8, cursor: onSelect ? 'pointer' : 'default',
                  background: 'var(--bg-secondary)',
                  transition: 'background 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-surface-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
              >
                <div style={{ minWidth: 0 }}>
                  <div className="text-mono" style={{ fontSize: 13, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {title}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {subtitle && <span>{subtitle}</span>}
                    <span>{rel.sample_id?.substring(0, 12) || 'unknown'}...</span>
                  </div>
                </div>
                <span style={{
                  padding: '4px 10px', borderRadius: 4, fontSize: 12, fontWeight: 600, flexShrink: 0,
                  background: style.bg, color: style.color,
                }}>
                  {Math.round(rel.similarity * 100)}% · {style.label}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

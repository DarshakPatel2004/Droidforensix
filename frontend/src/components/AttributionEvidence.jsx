import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import ConfidenceBar from './ConfidenceBar'
import { fetchWithCache } from '../utils/fetchWithCache'

export default function AttributionEvidence({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    setLoading(true)
    fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`)
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e); setLoading(false) })
  }, [sampleId, apiUrl])

  if (loading) return <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>Loading attribution evidence...</div>
  if (error) return <div className="card" style={{ padding: 24, color: 'var(--accent-rose)' }}>Failed to load: {error.message || error}</div>
  if (!data) return null

  const breakdown = data.confidence_breakdown || {}
  const rawSignals = data.supporting_signals
  const signals = Array.isArray(rawSignals) ? rawSignals : []
  const rawRelated = data.related_samples
  const related = Array.isArray(rawRelated) ? rawRelated : []
  const codeRefs = data.code_references || null

  const confidence = typeof data.confidence === 'number' ? data.confidence : 0
  const familyColor = confidence >= 0.9 ? 'var(--accent-emerald)'
    : confidence >= 0.7 ? 'var(--accent-cyan)'
    : confidence >= 0.5 ? 'var(--accent-amber)'
    : 'var(--accent-rose)'

  const dimensions = [
    { key: 'permissions_match', label: 'Permissions Match' },
    { key: 'c2_overlap', label: 'C2 Overlap' },
    { key: 'obfuscation_pattern', label: 'Obfuscation Pattern' },
    { key: 'code_similarity', label: 'Code Similarity' },
  ]

  return (
    <div className="card animate-fade-in">
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 4 }}>
          MAFIA Attribution
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 8 }}>
          <span style={{ fontSize: 22, fontWeight: 700 }}>{data.family || 'Unknown'}</span>
          <span style={{
            padding: '3px 10px', borderRadius: 6, fontSize: 13, fontWeight: 600,
            background: `${familyColor}22`, color: familyColor,
          }}>
            {Math.round(confidence * 100)}% confidence
          </span>
        </div>
      </div>

      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 14 }}>
          Confidence Breakdown
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {dimensions.map(dim => (
            <ConfidenceBar
              key={dim.key}
              value={breakdown[dim.key] || 0}
              label={dim.label}
            />
          ))}
        </div>
      </div>

      {signals.length > 0 && (
        <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Supporting Signals
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {signals.map((signal, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 13, color: 'var(--text-secondary)',
              }}>
                <span style={{ color: 'var(--accent-emerald)' }}>✓</span>
                {signal}
              </div>
            ))}
          </div>
        </div>
      )}

      {related.length > 0 && (
        <div style={{ padding: '16px 24px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Related Samples ({related.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {related.map((rel, i) => {
              const sim = typeof rel?.similarity === 'number' ? rel.similarity : 0
              const title = rel?.package_name || rel?.family || 'unknown'
              return (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '8px 12px', borderRadius: 6,
                background: 'var(--bg-secondary)', fontSize: 13, gap: 8,
              }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {title}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {rel?.family && rel.family !== title && <span>{rel.family}</span>}
                    <span className="text-mono">{rel?.sample_id?.substring(0, 12) || 'unknown'}...</span>
                  </div>
                </div>
                <span style={{
                  fontWeight: 600, flexShrink: 0,
                  color: sim >= 0.9 ? 'var(--accent-emerald)'
                    : sim >= 0.7 ? 'var(--accent-cyan)'
                    : 'var(--text-muted)',
                }}>
                  {Math.round(sim * 100)}% similar
                </span>
              </div>
              )
            })}
          </div>
        </div>
      )}

      {codeRefs && codeRefs.total_strings > 0 && (
        <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Code References &amp; Strings ({codeRefs.total_strings} total)
          </div>
          {Object.keys(codeRefs.by_category || {}).length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
              {Object.entries(codeRefs.by_category).map(([cat, count]) => (
                <span key={cat} className="badge neutral" style={{ fontSize: 10 }}>
                  {cat.replace(/_/g, ' ')}: {count}
                </span>
              ))}
            </div>
          )}
          {codeRefs.notable_strings?.length > 0 && (
            <div style={{ maxHeight: 360, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {codeRefs.notable_strings.map((s, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
                  padding: '4px 8px', borderRadius: 4, background: 'var(--bg-secondary)',
                }}>
                  <span style={{
                    padding: '1px 5px', borderRadius: 3, fontSize: 9, fontWeight: 600, flexShrink: 0,
                    background: s.entropy >= 6.5 ? 'rgba(244,63,94,0.1)' : s.entropy >= 4 ? 'rgba(245,158,11,0.1)' : 'rgba(16,185,129,0.1)',
                    color: s.entropy >= 6.5 ? 'var(--accent-rose)' : s.entropy >= 4 ? 'var(--accent-amber)' : 'var(--accent-emerald)',
                  }}>
                    {s.entropy.toFixed(1)}
                  </span>
                  <span className="text-mono" style={{ fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    &quot;{s.value}&quot;
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
          Recommended Actions
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div className="action">
            <b>1.</b> Block package name <span className="text-mono" style={{ color: 'var(--accent-rose)' }}>{data.family || 'this family'}</span> on app stores
          </div>
          <div className="action">
            <b>2.</b> Sinkhole C2 domains identified in threat intelligence
          </div>
          <div className="action">
            <b>3.</b> Alert users with <span className="text-mono">{data.family || 'matching'}</span> signature installed
          </div>
        </div>
      </div>
    </div>
  )
}

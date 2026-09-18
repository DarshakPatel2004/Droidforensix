import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */
import ThreatBadge from './ThreatBadge'
import LoadingSpinner from './LoadingSpinner'

export default function ThreatSummary({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    setLoading(true)
    fetch(`${apiUrl}/api/sample/${sampleId}/threat-summary`)
      .then(r => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e); setLoading(false) })
  }, [sampleId, apiUrl])

  if (loading) return <div className="card" style={{ padding: 24 }}><LoadingSpinner message="Loading threat summary..." /></div>
  if (error) return <div className="card" style={{ padding: 24, color: 'var(--accent-rose)' }}>Failed to load: {error}</div>
  if (!data) return null

  const severity = data.threat_level || 'LOW'
  const flags = data.red_flags || []

  return (
    <div className="card animate-fade-in" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 4 }}>
              Sample
            </div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>{data.package_name || 'Unknown package'}</div>
            {data.version_name && (
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>v{data.version_name}</div>
            )}
          </div>
          <div style={{ textAlign: 'right' }}>
            <ThreatBadge level={severity} label={`${severity} (${data.threat_score}/100)`} size="lg" />
          </div>
        </div>
      </div>

      <div style={{ padding: '16px 24px', display: 'flex', gap: 40, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Family</div>
          <div style={{ fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            {data.family !== 'unknown' ? data.family : 'Unidentified'}
            <ThreatBadge level={data.confidence >= 0.9 ? 'CRITICAL' : data.confidence >= 0.7 ? 'HIGH' : 'MEDIUM'} label={`${Math.round(data.confidence * 100)}% confidence`} size="sm" />
          </div>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Similar Samples</div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{data.similar_samples_count}</div>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>C2 Indicators</div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{data.c2_count || 0}</div>
        </div>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Obfuscation Score</div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{data.obfuscation_score || 0}/100</div>
        </div>
      </div>

      <div style={{ padding: '0 24px 20px' }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 12 }}>
          Red Flags
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
          {flags.map((flag, i) => {
            const isHigh = flag.type === 'active_c2_endpoints' || flag.type === 'obfuscation'
            const flagColor = isHigh ? 'var(--accent-rose)' : 'var(--accent-amber)'
            const flagBg = isHigh ? 'rgba(244,63,94,0.1)' : 'rgba(245,158,11,0.1)'
            return (
              <div key={i} style={{
                padding: '10px 14px', borderRadius: 8,
                background: flagBg, border: '1px solid transparent',
              }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'capitalize' }}>
                  {flag.type.replace(/_/g, ' ')}
                </div>
                <div style={{ fontWeight: 600, fontSize: 14, color: flagColor }}>
                  {flag.count !== undefined ? flag.count : flag.level || 'N/A'}
                </div>
              </div>
            )
          })}
          {flags.length === 0 && (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No significant red flags detected</div>
          )}
        </div>
      </div>

      <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-color)', display: 'flex', gap: 10 }}>
        <button className="primary" onClick={() => window.open(`#`, '_blank')} style={{ padding: '8px 18px', fontSize: 12 }}>
          Investigate
        </button>
        <button className="secondary" onClick={() => {}} style={{ padding: '8px 18px', fontSize: 12 }}>
          Block
        </button>
        <button className="secondary" onClick={() => {}} style={{ padding: '8px 18px', fontSize: 12 }}>
          Watchlist
        </button>
      </div>
    </div>
  )
}

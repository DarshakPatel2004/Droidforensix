import { useState, useEffect } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */

function safeStr(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'string' || typeof v === 'number') return String(v)
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

export default function ManifestTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    setFetchError(null)
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/manifest`)
      .then(r => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then(d => { setData(d?.manifest || null); setLoading(false) })
      .catch(e => { setFetchError(e || true); setLoading(false) })
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading manifest...</div>
  if (fetchError) return <div className="empty-state">Failed to load manifest data</div>
  if (!data || typeof data !== 'object') return <div className="empty-state">No manifest data available</div>

  const app = data.application && typeof data.application === 'object' ? data.application : {}

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="card" style={{ padding: '12px 16px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>Package</div>
          <div className="text-mono" style={{ fontSize: 13 }}>{safeStr(data.package)}</div>
        </div>
        <div className="card" style={{ padding: '12px 16px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>Version</div>
          <div className="text-mono" style={{ fontSize: 13 }}>{safeStr(data.version_name)} (code {safeStr(data.version_code)})</div>
        </div>
        <div className="card" style={{ padding: '12px 16px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>SDK</div>
          <div className="text-mono" style={{ fontSize: 13 }}>min {safeStr(data.min_sdk)} / target {safeStr(data.target_sdk)}</div>
        </div>
      </div>

      {Object.keys(app).length > 0 && (
        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Application Attributes
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 8 }}>
            {Object.entries(app).map(([key, val]) => (
              <div key={key} style={{ fontSize: 13 }}>
                <span style={{ color: 'var(--text-muted)' }}>{key}: </span>
                <span className="text-mono">{safeStr(val)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {Array.isArray(data.features) && data.features.length > 0 && (
        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Required Features
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {data.features.map((f, i) => (
              <span key={i} className="badge neutral">{safeStr(f)}</span>
            ))}
          </div>
        </div>
      )}

      {typeof data.raw_manifest === 'string' && (
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Raw Manifest
          </div>
          <pre style={{
            maxHeight: 300, overflow: 'auto', fontSize: 11, lineHeight: 1.4,
            background: 'var(--bg-secondary)', padding: 12, borderRadius: 6,
            margin: 0,
          }}>
            {data.raw_manifest.substring(0, 5000)}
          </pre>
        </div>
      )}
    </div>
  )
}

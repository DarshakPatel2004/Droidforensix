import { useState, useEffect } from 'react'

const PROTECTION_STYLES = {
  dangerous: { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)' },
  signature: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.1)' },
  normal: { color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.1)' },
  unknown: { color: 'var(--text-muted)', bg: 'var(--bg-surface)' },
}

export default function PermissionsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/permissions`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d.permissions); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading permissions...</div>
  if (!data?.length) return <div className="empty-state">No permissions declared</div>

  const groups = { dangerous: [], signature: [], normal: [], other: [] }
  data.forEach(p => {
    const level = p.protection_level || 'normal'
    if (groups[level]) groups[level].push(p)
    else groups.other.push(p)
  })

  const filtered = filter === 'all' ? data : groups[filter] || []

  const tableStyle = {
    width: '100%', borderCollapse: 'collapse', fontSize: 12,
  }
  const thStyle = {
    textAlign: 'left', padding: '8px 10px', fontSize: 10, fontWeight: 700,
    textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)',
    borderBottom: '1px solid var(--border-color)', whiteSpace: 'nowrap',
    background: 'var(--bg-secondary)',
  }
  const tdStyle = {
    padding: '8px 10px', borderBottom: '1px solid var(--border-color)',
    verticalAlign: 'top', color: 'var(--text-secondary)',
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        {[
          { id: 'all', label: `All (${data.length})` },
          { id: 'dangerous', label: `Dangerous (${groups.dangerous.length})` },
          { id: 'signature', label: `Signature (${groups.signature.length})` },
          { id: 'normal', label: `Normal (${groups.normal.length})` },
        ].map(g => (
          <button key={g.id} onClick={() => setFilter(g.id)} style={{
            padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
            fontSize: 12, fontWeight: 600,
            background: filter === g.id ? 'var(--accent-cyan)' : 'var(--bg-surface)',
            color: filter === g.id ? '#fff' : 'var(--text-secondary)',
          }}>{g.label}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          Showing {filtered.length} of {data.length} permissions
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>Permission</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Protection Level</th>
              <th style={thStyle}>Label</th>
              <th style={thStyle}>Description</th>
              <th style={thStyle}>AOSP</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((p, i) => {
              const level = p.protection_level || 'normal'
              const style = PROTECTION_STYLES[level] || PROTECTION_STYLES.unknown
              return (
                <tr key={i} style={{ background: i % 2 === 0 ? 'transparent' : 'var(--bg-secondary)' }}>
                  <td style={{ ...tdStyle, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-primary)' }}>
                    {p.name}
                  </td>
                  <td style={tdStyle}>
                    <span style={{
                      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 600,
                      background: 'var(--bg-surface)', color: 'var(--text-muted)',
                      border: '1px solid var(--border-color)',
                    }}>
                      {p.type === 'declared_permission' ? 'declared' : 'uses'}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <span className="badge" style={{ background: style.bg, color: style.color }}>
                      {level}
                    </span>
                  </td>
                  <td style={tdStyle}>{p.label || '—'}</td>
                  <td style={tdStyle}>{p.description || '—'}</td>
                  <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                    <span style={{ color: p.is_aosp ? 'var(--accent-emerald)' : 'var(--text-muted)' }}>
                      {p.is_aosp ? '✓' : '—'}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

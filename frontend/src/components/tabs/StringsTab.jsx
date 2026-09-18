import { useState, useEffect, useMemo, useCallback } from 'react'

function classifyFormat(s) {
  if (!s || s.length === 0) return 'empty'
  if (s.length < 3) return 'short'
  const printable = s.split('').filter(c => c >= ' ' && c <= '~').length / s.length
  if (printable < 0.6) return 'binary'
  if (/^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length > 12 && s.length % 4 === 0) return 'base64'
  if (/^[0-9a-fA-F]+$/.test(s) && s.length > 8 && s.length % 2 === 0) return 'hex'
  if (/^https?:\/\//i.test(s)) return 'url'
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s)) return 'ip'
  if (s.includes('/') || s.includes('\\')) return 'path'
  if (/^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+/.test(s)) return 'email'
  return 'plain'
}

function tryDecode(s, type) {
  try {
    if (type === 'base64') { const d = atob(s); if (d.split('').every(c => c >= ' ' && c <= '~')) return d }
    if (type === 'hex') { const d = s.match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join(''); if (d.split('').every(c => c >= ' ' && c <= '~')) return d }
    if (type === 'url') { const d = decodeURIComponent(s); if (d !== s) return d }
  } catch { /* not decodable */ }
  return null
}

const PAYLOAD_PATTERNS = /\.apk$|\.dex$|\.jar$|payload|dropper|classes[23]\.dex/i
const C2_PATTERNS = /https?:\/\/|\.(com|net|org|xyz|top|ru|cn|info)\/|api\.|cdn\./i
const SERVICE_PATTERNS = /service|provider|receiver|activity|intent/i
const SOCIAL_PATTERNS = /update|version|new (version|update)|发现新版本|闪电更新|立即升级|免费|免费版/i
const CRYPTO_PATTERNS = /(AES|RSA|DES|SHA|MD5|Cipher|SecretKey|KeyStore)/i

function classifyRisk(str, decoded) {
  const text = decoded || str
  if (PAYLOAD_PATTERNS.test(text)) return { level: 'critical', label: 'Payload File', risk: 'CRITICAL' }
  if (C2_PATTERNS.test(text)) return { level: 'critical', label: 'C2 Indicator', risk: 'CRITICAL' }
  if (SERVICE_PATTERNS.test(text)) return { level: 'critical', label: 'Service Spoofing', risk: 'CRITICAL' }
  if (SOCIAL_PATTERNS.test(text)) return { level: 'suspicious', label: 'Social Engineering', risk: 'HIGH' }
  if (CRYPTO_PATTERNS.test(text)) return { level: 'suspicious', label: 'Crypto Usage', risk: 'MEDIUM' }
  if (classifyFormat(str) !== 'plain') return { level: 'suspicious', label: 'Encoded', risk: 'MEDIUM' }
  return { level: 'benign', label: 'Benign', risk: 'LOW' }
}

const RISK_META = {
  critical: { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)', order: 0 },
  suspicious: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.08)', order: 1 },
  benign: { color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.06)', order: 2 },
}

const FORMAT_META = {
  url: { color: 'var(--accent-cyan)' }, ip: { color: 'var(--accent-rose)' },
  base64: { color: 'var(--accent-amber)' }, hex: { color: 'var(--accent-violet)' },
  path: { color: 'var(--accent-emerald)' }, email: { color: 'var(--accent-cyan)' },
  binary: { color: 'var(--accent-rose)' }, plain: { color: 'var(--text-muted)' },
  short: { color: 'var(--text-muted)' }, empty: { color: 'var(--text-muted)' },
}

function copyToClipboard(text) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

export default function StringsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/strings`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  const allStrings = useMemo(() => {
    const raw = data?.string_literals || data?.categories?.string_literals || []
    return raw.map(s => {
      const str = typeof s === 'string' ? s : typeof s === 'number' ? String(s) : s?.value || s?.text || JSON.stringify(s)
      const fmt = classifyFormat(str)
      const dec = tryDecode(str, fmt)
      const risk = classifyRisk(str, dec)
      return { raw: str, fmt, decoded: dec, risk, hex: str}
    })
  }, [data])

  const groupCounts = useMemo(() => {
    const c = { critical: 0, suspicious: 0, benign: 0 }
    allStrings.forEach(s => c[s.risk.level]++)
    return c
  }, [allStrings])

  const filtered = useMemo(() => {
    let list = allStrings
    if (riskFilter !== 'all') list = list.filter(s => s.risk.level === riskFilter)
    if (search) list = list.filter(s => s.raw.toLowerCase().includes(search.toLowerCase()) || (s.decoded && s.decoded.toLowerCase().includes(search.toLowerCase())))
    return list
  }, [allStrings, riskFilter, search])

  const grouped = useMemo(() => {
    const g = { critical: [], suspicious: [], benign: [] }
    filtered.forEach(s => { if (g[s.risk.level]) g[s.risk.level].push(s) })
    return g
  }, [filtered])

  const loadRefs = useCallback(async (str) => {
    if (expanded === str) { setExpanded(null); return }
    try {
      const res = await fetch(`${apiUrl}/api/sample/${sampleId}/string-references/${encodeURIComponent(str)}`)
      if (res.ok) {
        const refs = await res.json()
        setExpanded({ str, usages: refs.usages || [] })
      } else {
        setExpanded({ str, usages: [] })
      }
    } catch {
      setExpanded({ str, usages: [] })
    }
  }, [sampleId, apiUrl, expanded])

  if (loading) return <div className="empty-state">Loading strings...</div>
  if (!data) return <div className="empty-state">No strings data available</div>

  const riskGroups = [
    { id: 'critical', label: 'Critical', count: groupCounts.critical },
    { id: 'suspicious', label: 'Suspicious', count: groupCounts.suspicious },
    { id: 'benign', label: 'Benign', count: groupCounts.benign },
  ]

  return (
    <div>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          placeholder="Search strings..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: 200, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
          }}
        />
        <div style={{ display: 'flex', gap: 4 }}>
          <button onClick={() => setRiskFilter('all')} style={{
            padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: 600,
            background: riskFilter === 'all' ? 'var(--accent-cyan)' : 'var(--bg-surface)',
            color: riskFilter === 'all' ? '#fff' : 'var(--text-secondary)',
          }}>All ({allStrings.length})</button>
          {riskGroups.map(g => g.count > 0 && (
            <button key={g.id} onClick={() => setRiskFilter(g.id)} style={{
              padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 11, fontWeight: 600,
              background: riskFilter === g.id ? RISK_META[g.id].color : RISK_META[g.id].bg,
              color: riskFilter === g.id ? '#fff' : RISK_META[g.id].color,
            }}>{g.label} ({g.count})</button>
          ))}
        </div>
      </div>

      {['critical', 'suspicious', 'benign'].map(level => {
        const items = grouped[level]
        if (!items.length) return null
        const meta = RISK_META[level]
        return (
          <div key={level} style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: meta.color, marginBottom: 8, padding: '0 4px' }}>
              {level.toUpperCase()} — {items.length} string{items.length > 1 ? 's' : ''}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {items.slice(0, 200).map((s, i) => {
                const fmtColor = FORMAT_META[s.fmt]?.color || 'var(--text-muted)'
                const isExpanded = expanded?.str === s.raw
                return (
                  <div key={i}>
                    <div
                      onClick={() => loadRefs(s.raw)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        padding: '6px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                        fontFamily: "'JetBrains Mono', monospace",
                        background: isExpanded ? 'var(--bg-surface)' : (i % 2 === 0 ? 'transparent' : 'var(--bg-secondary)'),
                        color: 'var(--text-secondary)',
                      }}
                    >
                      <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 600, background: meta.bg, color: meta.color, flexShrink: 0 }}>
                        {s.risk.label}
                      </span>
                      <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 8, color: fmtColor, flexShrink: 0 }}>
                        {s.fmt}
                      </span>
                      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        &quot;{s.raw.substring(0, 100)}&quot;
                      </span>
                      <button
                        onClick={e => { e.stopPropagation(); copyToClipboard(s.raw) }}
                        style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer', padding: '2px 4px' }}
                        title="Copy"
                      >[copy]</button>
                      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{isExpanded ? '▲' : '▼'}</span>
                    </div>
                    {isExpanded && (
                      <div style={{ padding: '8px 12px 8px 60px', fontSize: 11, background: 'var(--bg-surface)', borderRadius: '0 0 4px 4px', marginBottom: 2 }}>
                        {expanded.usages.length === 0 ? (
                          <span style={{ color: 'var(--text-muted)' }}>No code references found</span>
                        ) : (
                          expanded.usages.map((u, j) => (
                            <div key={j} style={{ marginBottom: 4, lineHeight: 1.5 }}>
                              <span className="text-mono" style={{ color: 'var(--accent-cyan)' }}>{u.method}()</span>
                              <span style={{ color: 'var(--text-muted)' }}> L{u.line}: </span>
                              <span style={{ color: 'var(--text-secondary)' }}>{u.context || u.usage || ''}</span>
                            </div>
                          ))
                        )}
                        {s.decoded && (
                          <div style={{ marginTop: 4, color: 'var(--accent-emerald)', fontSize: 10 }}>
                            Decoded: &quot;{s.decoded.substring(0, 200)}&quot;
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
              {items.length > 200 && (
                <div style={{ color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: 8 }}>
                  + {items.length - 200} more {level} strings
                </div>
              )}
            </div>
          </div>
        )
      })}
      {filtered.length === 0 && (
        <div className="empty-state">No strings match your search</div>
      )}
    </div>
  )
}

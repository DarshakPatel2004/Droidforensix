import { useState, useEffect } from 'react'

const ARCH_ICONS = {
  'armeabi-v7a': '📱',
  'arm64-v8a': '📱',
  'x86': '💻',
  'x86_64': '💻',
}

const TECH_LABELS = {
  xor_single: 'XOR (single-byte)',
  xor_multi: 'XOR (multi-byte)',
  sub_cipher: 'SUB cipher',
  add_cipher: 'ADD cipher',
  rot47: 'ROT47',
}

const RISK_COLORS = { CRITICAL: 'var(--accent-rose)', HIGH: 'var(--accent-amber)', MEDIUM: 'var(--accent-yellow)', LOW: 'var(--accent-cyan)' }

function DeobfItem({ item }) {
  const [open, setOpen] = useState(false)
  const decoded = item.decoded || ''
  return (
    <div style={{ border: '1px solid var(--border-color)', borderRadius: 5, padding: '6px 8px', background: 'var(--bg-surface)' }}>
      <div onClick={() => setOpen(!open)} style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flex: 1 }}>
          <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: 'var(--accent-cyan)', whiteSpace: 'nowrap' }}>
            {TECH_LABELS[item.technique] || item.technique}
          </span>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'nowrap' }}>
            key={item.key} score={item.score}
          </span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{open ? '▲' : '▼'}</span>
      </div>
      <code style={{ display: 'block', marginTop: 3, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--text-primary)', wordBreak: 'break-all', lineHeight: 1.4 }}>
        {decoded.length > 100 && !open ? decoded.slice(0, 100) + '...' : decoded}
      </code>
    </div>
  )
}

function LibDetailCard({ lib }) {
  const [open, setOpen] = useState(false)
  const ea = lib.elf_analysis || {}
  const deobs = ea.deobfuscated_strings || lib.deobfuscated_strings || []
  const risk = ea.risk_score || {}
  const packing = ea.packing || {}
  const riskColor = RISK_COLORS[risk.level] || 'var(--text-secondary)'

  return (
    <div style={{ border: '1px solid var(--border-color)', borderRadius: 8, overflow: 'hidden', background: 'var(--bg-surface)' }}>
      <div onClick={() => setOpen(!open)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', borderBottom: open ? '1px solid var(--border-color)' : 'none' }}>
        <span style={{ flex: 1, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
          {lib.name || lib.path || 'unknown'}
        </span>
        {risk.level && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: riskColor + '20', color: riskColor, fontWeight: 700 }}>{risk.level}</span>}
        {packing.level && packing.level !== 'none' && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--accent-amber)20', color: 'var(--accent-amber)', fontWeight: 600 }}>packed</span>}
        {deobs.length > 0 && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'var(--accent-cyan)20', color: 'var(--accent-cyan)', fontWeight: 600 }}>{deobs.length} decoded</span>}
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div style={{ padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-secondary)' }}>
            <span>Size: {ea.size_bytes || lib.size || 0} bytes</span>
            <span>Arch: {ea.header?.arch || lib.arch || '?'}</span>
            <span>Class: {ea.header?.class || '?'}</span>
            {ea.jni_exports?.length > 0 && <span>JNI: {ea.jni_exports.length} exports</span>}
            {ea.suspicious_strings?.length > 0 && <span>Suspicious: {ea.suspicious_strings.length}</span>}
            {ea.embedded_blobs?.length > 0 && <span>Embedded: {ea.embedded_blobs.length}</span>}
          </div>

          {(ea.jni_exports || []).length > 0 && (
            <div>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>JNI Exports</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 3 }}>
                {ea.jni_exports.map((e, i) => (
                  <span key={i} style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-rose)', padding: '1px 5px', background: 'var(--bg-primary)', borderRadius: 3 }}>
                    {e.symbol || e.class || e}
                  </span>
                ))}
              </div>
            </div>
          )}

          {(ea.suspicious_strings || []).length > 0 && (
            <div>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Suspicious Strings</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 3 }}>
                {ea.suspicious_strings.map((s, i) => (
                  <span key={i} style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-violet)', padding: '1px 5px', background: 'var(--bg-primary)', borderRadius: 3 }}>
                    {s.value || s.type || s}
                  </span>
                ))}
              </div>
            </div>
          )}

          {deobs.length > 0 && (
            <div>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                Deobfuscated Strings ({deobs.length})
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
                {deobs.map((item, i) => <DeobfItem key={i} item={item} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function NativeLibsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading native libraries...</div>

  const nativeLibs = data?.native_libs || []
  if (nativeLibs.length === 0) return <div className="empty-state">No native libraries found</div>

  const byArch = {}
  nativeLibs.forEach(lib => {
    const arch = lib.arch || lib.architecture || 'unknown'
    if (!byArch[arch]) byArch[arch] = []
    byArch[arch].push(lib)
  })

  return (
    <div>
      {Object.entries(byArch).map(([arch, libs]) => (
        <div key={arch} style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 18 }}>{ARCH_ICONS[arch] || '📦'}</span>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{arch}</span>
            <span className="badge neutral" style={{ fontSize: 10 }}>{libs.length} libs</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {libs.map((lib, i) => (
              typeof lib === 'string'
                ? <div key={i} style={{ display: 'flex', alignItems: 'center', padding: '8px 12px', borderRadius: 6, background: 'var(--bg-secondary)', fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-secondary)' }}>{lib}</div>
                : <LibDetailCard key={i} lib={lib} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

import { useState, useEffect, useCallback } from 'react'
import '../styles/ObfuscationView.css'

const TECH_COLORS = ['rose', 'amber', 'cyan', 'violet']

const TECH_LABELS = {
  xor_single: 'XOR (single-byte)',
  xor_multi: 'XOR (multi-byte)',
  sub_cipher: 'SUB cipher',
  add_cipher: 'ADD cipher',
  rot47: 'ROT47',
}

function DeobfCard({ item }) {
  const [open, setOpen] = useState(false)
  const decoded = item.decoded || ''
  return (
    <div style={{
      border: '1px solid var(--border-color)',
      borderRadius: 6, padding: '8px 10px',
      background: 'var(--bg-primary)',
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flex: 1 }}>
          <span style={{
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
            color: 'var(--accent-cyan)', whiteSpace: 'nowrap',
          }}>
            {TECH_LABELS[item.technique] || item.technique}
          </span>
          <span style={{
            fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'nowrap',
          }}>
            key={item.key} score={item.score}
          </span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{open ? '▲' : '▼'}</span>
      </div>
      <code style={{
        display: 'block', marginTop: 4,
        fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
        color: 'var(--text-primary)', wordBreak: 'break-all',
        lineHeight: 1.5,
      }}>
        {decoded.length > 120 && !open ? decoded.slice(0, 120) + '...' : decoded}
      </code>
    </div>
  )
}

function LibCard({ lib }) {
  const [open, setOpen] = useState(false)
  const deobs = lib.deobfuscated_strings || []
  const name = lib.library || 'unknown'
  const shortName = name.split('/').pop()
  return (
    <div style={{
      border: '1px solid var(--border-color)',
      borderRadius: 8, overflow: 'hidden',
      background: 'var(--bg-surface)',
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px', cursor: 'pointer',
          background: open ? 'var(--bg-primary)' : 'transparent',
          borderBottom: open ? '1px solid var(--border-color)' : 'none',
        }}
      >
        <span style={{ fontSize: 16 }}>📦</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', fontFamily: "'JetBrains Mono', monospace" }}>
            {shortName}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span>{lib.arch} / {lib.class}</span>
            <span>risk: {lib.risk_level} ({lib.risk_score})</span>
            {lib.packing_level !== 'none' && <span>packing: {lib.packing_level}</span>}
            {deobs.length > 0 && <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{deobs.length} deobfuscated</span>}
          </div>
        </div>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {lib.jni_exports_count > 0 && (
            <div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>JNI Exports: {lib.jni_exports_count}</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                {(lib.jni_exports || []).map((e, i) => (
                  <span key={i} style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-rose)', padding: '2px 6px', background: 'var(--bg-primary)', borderRadius: 4 }}>
                    {e.symbol || e.class || e}
                  </span>
                ))}
              </div>
            </div>
          )}

          {lib.anti_analysis_count > 0 && (
            <div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Anti-Analysis: {lib.anti_analysis_count}</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                {(lib.anti_analysis || []).map((a, i) => (
                  <span key={i} style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-amber)', padding: '2px 6px', background: 'var(--bg-primary)', borderRadius: 4 }}>
                    {a.value || a.type || a}
                  </span>
                ))}
              </div>
            </div>
          )}

          {lib.suspicious_strings_count > 0 && (
            <div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Suspicious Strings: {lib.suspicious_strings_count}</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                {(lib.suspicious_strings || []).map((s, i) => (
                  <span key={i} style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-violet)', padding: '2px 6px', background: 'var(--bg-primary)', borderRadius: 4 }}>
                    {s.value || s}
                  </span>
                ))}
              </div>
            </div>
          )}

          {deobs.length > 0 && (
            <div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                Deobfuscated Strings ({deobs.length})
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {deobs.map((item, i) => <DeobfCard key={i} item={item} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function ObfuscationView({ sample, apiUrl, result }) {
  const [obfuscationData, setObfuscationData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [deobfInput, setDeobfInput] = useState('')
  const [deobfHint, setDeobfHint] = useState('')
  const [deobfResult, setDeobfResult] = useState(null)
  const [deobfLoading, setDeobfLoading] = useState(false)

  const packing = result?.binary_packing || {}
  const reflective = result?.reflective_tracing || {}
  const strings = result?.string_clustering || {}
  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const API_URL = apiUrl || 'http://localhost:8000'

  const fetchObfuscation = useCallback(async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_URL}/api/sample/${sampleId}/obfuscation`)
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setObfuscationData(data)
      setError(null)
    } catch (err) {
      setError('Failed to load obfuscation analysis: ' + err.message)
    } finally {
      setLoading(false)
    }
  }, [sampleId, API_URL])

  const runDeobfuscation = async () => {
    if (!deobfInput.trim() || !sampleId) return
    try {
      setDeobfLoading(true)
      const response = await fetch(`${API_URL}/api/sample/${sampleId}/deobfuscate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: deobfInput, hint: deobfHint || undefined }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setDeobfResult(data)
    } catch (err) {
      setDeobfResult({ original: deobfInput, results: [{ type: 'error', value: err.message, status: 'error' }] })
    } finally {
      setDeobfLoading(false)
    }
  }

  useEffect(() => {
    if (!sampleId) return
    fetchObfuscation() // eslint-disable-line react-hooks/set-state-in-effect
  }, [sampleId, fetchObfuscation])

  if (!sample) {
    return (
      <div className="state-container">
        <span className="state-icon">🔐</span>
        <h3 className="state-title">No sample selected</h3>
        <p className="state-description">Analyze an APK first to view obfuscation analysis.</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="state-container">
        <div className="analysis-loading-spinner"></div>
        <h3 className="state-title">Loading Obfuscation Analysis</h3>
        <p className="state-description">Scanning for reflection, dynamic loading, crypto APIs, and packing...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="state-container error-container">
        <span className="state-icon">⚠</span>
        <h3 className="state-title">Obfuscation Analysis Error</h3>
        <p className="state-description">{error}</p>
      </div>
    )
  }

  if (!obfuscationData) {
    return (
      <div className="state-container">
        <span className="state-icon">📭</span>
        <h3 className="state-title">No obfuscation data</h3>
        <p className="state-description">Obfuscation analysis was not available for this sample.</p>
      </div>
    )
  }

  const score = Math.round(obfuscationData.obfuscation_score || 0)
  const level = obfuscationData.obfuscation_level || 'low'
  const techniques = obfuscationData.techniques || []
  const techGrid = techniques.slice(0, 4).map((t, i) => ({
    name: t.name || t.key,
    percent: Math.min(t.count * 10, 99),
    api: t.items?.[0]?.class || t.items?.[0]?.detail || '',
    color: TECH_COLORS[i] || 'cyan',
  }))

  return (
    <div className="obfuscation-view">
      <div className="obf-head">
        <div>
          <p className="section-title">EVASION ASSESSMENT</p>
          <h2>Obfuscation score <span style={{ color: `var(--risk-${level})` }}>{score}/100</span></h2>
        </div>
        <div className="obf-meter" style={{ width: '100%', maxWidth: 300 }}>
          <div className="meter-bg">
            <div className="meter-fill" style={{ width: `${score}%`, background: `var(--risk-${level})` }} />
          </div>
        </div>
      </div>

      {techniques.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <h3 style={{ margin: 0, color: 'var(--text-primary)' }}>No obfuscation indicators detected</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>The sample scored {score}/100.</p>
        </div>
      ) : (
        <div className="tech-grid">
          {techGrid.map(t => (
            <section className="tech-card" key={t.name}>
              <small>{t.name}</small>
              <strong>{t.percent}%</strong>
              <div className="meter-bg" style={{ height: 6 }}>
                <div className="meter-fill" style={{ width: `${t.percent}%`, background: `var(--accent-${t.color})` }} />
              </div>
              <p className="text-mono" style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>{t.api}</p>
            </section>
          ))}
        </div>
      )}

      {result && (
        <div className="obfuscation-grid">
          {packing.packing_detected && (
            <div className="obfuscation-card card">
              <h3 className="section-title">Binary Packing</h3>
              <div className="native-list">
                <div className="native-item">
                  <span className="native-name">Obfuscation Score</span>
                  <span className="native-meta">{packing.obfuscation_score ?? 0}/100</span>
                </div>
                <div className="native-item">
                  <span className="native-name">Indicators</span>
                  <span className="native-meta">{(packing.indicators || []).join(', ') || 'none'}</span>
                </div>
              </div>
            </div>
          )}

          {reflective.total_reflective_calls > 0 && (
            <div className="obfuscation-card card">
              <h3 className="section-title">Reflective Tracing</h3>
              <div className="native-list">
                <div className="native-item">
                  <span className="native-name">Total Reflective Calls</span>
                  <span className="native-meta">{reflective.total_reflective_calls}</span>
                </div>
                <div className="native-item">
                  <span className="native-name">Sensitive API Targets</span>
                  <span className="native-meta">{reflective.total_sensitive ?? 0}</span>
                </div>
              </div>
            </div>
          )}

          {strings.total_high_entropy > 0 && (
            <div className="obfuscation-card card">
              <h3 className="section-title">High-Entropy Strings</h3>
              <div className="native-list">
                <div className="native-item">
                  <span className="native-name">Total High-Entropy</span>
                  <span className="native-meta">{strings.total_high_entropy}</span>
                </div>
                <div className="native-item">
                  <span className="native-name">Clusters</span>
                  <span className="native-meta">{strings.total_clusters ?? 0}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {(obfuscationData.elf_analysis || []).length > 0 && (
        <section className="card" style={{ padding: '1.25rem' }}>
          <h3 className="section-title">Native Library ELF Analysis</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: 14, margin: '0 0 0.75rem' }}>
            Deobfuscated strings recovered from obfuscated ELF binaries via XOR/ROT/ADD cipher cracking.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {obfuscationData.elf_analysis.map((lib, i) => (
              <LibCard key={i} lib={lib} />
            ))}
          </div>
        </section>
      )}

      <section className="card" style={{ padding: '1.25rem' }}>
        <h3 className="section-title">Deobfuscation Tool</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14, margin: '0 0 0.75rem' }}>Paste an obfuscated string to try Base64, hex, URL, and XOR decoders.</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="e.g. SGVsbG8gV29ybGQ= or 48656c6c6f..."
            value={deobfInput}
            onChange={(e) => setDeobfInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runDeobfuscation()}
            style={{ flex: 1, minWidth: 200, padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: 6, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}
          />
          <select value={deobfHint} onChange={(e) => setDeobfHint(e.target.value)} style={{ padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: 6, color: 'var(--text-primary)' }}>
            <option value="">Auto-detect</option>
            <option value="base64">Base64</option>
            <option value="hex">Hex</option>
            <option value="url_decode">URL decode</option>
          </select>
          <button onClick={runDeobfuscation} disabled={deobfLoading} style={{ padding: '10px 20px', background: 'var(--accent-cyan)', border: 'none', borderRadius: 6, color: 'white', fontWeight: 600, cursor: 'pointer' }}>
            {deobfLoading ? 'Decoding...' : 'Decode'}
          </button>
        </div>

        {deobfResult && (
          <div className="deobf-results">
            <div className="deobf-original">
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Original:</span>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{deobfResult.original}</code>
            </div>
            {deobfResult.results.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No decodings produced printable output.</p>
            ) : (
              deobfResult.results.map((r, idx) => (
                <div key={idx} className={`deobf-result deobf-${r.status}`}>
                  <span className="deobf-type">{r.type}</span>
                  <code className="deobf-value">{r.value}</code>
                  {r.raw_bytes && <span className="deobf-raw">hex: {r.raw_bytes}</span>}
                </div>
              ))
            )}
          </div>
        )}
      </section>
    </div>
  )
}

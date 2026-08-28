import { useState, useEffect, useRef, useCallback } from 'react'
import ClassSourceViewer from '../ClassSourceViewer'
import ThreatBadge from '../ThreatBadge'
/* eslint-disable react-hooks/set-state-in-effect */

function copyText(text) {
  navigator.clipboard?.writeText(text).catch(() => {})
}

function downloadFile(content, filename, type = 'text/plain') {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

const patternDescriptions = {
  signature_check: { risk: 'MEDIUM', desc: 'Anti-analysis signature verification — validates app cert before executing malicious logic' },
  reflection: { risk: 'HIGH', desc: 'Reflection abuse — dynamically accesses restricted APIs or classes' },
  service_launch: { risk: 'CRITICAL', desc: 'Hidden service launch — may spoof Android system services' },
  payload_drop: { risk: 'CRITICAL', desc: 'Secondary malware payload — extracts and installs additional APK/DEX' },
  dynamic_loading: { risk: 'CRITICAL', desc: 'Dynamic code loading — loads DexClassLoader or PathClassLoader' },
  anti_analysis: { risk: 'MEDIUM', desc: 'Anti-analysis technique — detects emulator, debugger, or root' },
  crypto_usage: { risk: 'MEDIUM', desc: 'Cryptographic operation — may encrypt/obfuscate C2 traffic' },
  c2_communication: { risk: 'CRITICAL', desc: 'C2 communication — connects to remote command server' },
  data_exfiltration: { risk: 'CRITICAL', desc: 'Data exfiltration — sends sensitive data off-device' },
}

export default function CodeTab({ sampleId, apiUrl }) {
  const [classes, setClasses] = useState([])
  const [selectedClass, setSelectedClass] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [search, setSearch] = useState('')
  const [viewMode, setViewMode] = useState('analysis')
  const [hoveredLine, setHoveredLine] = useState(null)
  const [highlightString, setHighlightString] = useState(null)
  const [flowView, setFlowView] = useState('list')
  const [markedItems, setMarkedItems] = useState(new Set())
  const methodRefs = useRef({})

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes?limit=10000`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setClasses(d.classes || []) })
      .catch(() => {})
  }, [sampleId, apiUrl])

  useEffect(() => {
    if (!selectedClass || !sampleId) return
    setAnalysisLoading(true)
    setAnalysis(null)
    setHighlightString(null)
    fetch(`${apiUrl}/api/sample/${sampleId}/code-analysis/${encodeURIComponent(selectedClass)}`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setAnalysis(d); setAnalysisLoading(false) })
      .catch(() => setAnalysisLoading(false))
  }, [selectedClass, sampleId, apiUrl])

  const filtered = classes.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase())
  )

  const scrollToMethod = useCallback((methodName) => {
    const el = methodRefs.current[methodName]
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [])

  const navigateToSource = useCallback((str) => {
    setHighlightString(str)
    setViewMode('source')
  }, [])

  const toggleMark = useCallback((id) => {
    setMarkedItems(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }, [])

  const shareAnalysis = useCallback(() => {
    if (!analysis) return
    const lines = [
      `=== DroidForensix Code Analysis ===`,
      `Class: ${analysis.class_name}`,
      ``,
      `Attack Flow:`,
      ...(analysis.attack_flow || []).map(s => `  ${s.step}. ${s.method}() [${s.risk_level}] L${s.line} — ${s.description}`),
      ``,
      `Methods (${analysis.methods?.length || 0}):`,
      ...(analysis.methods || []).map(m => `  ${m.name}() [${m.risk_level}] L${m.start_line}–${m.end_line} — techniques: ${(m.techniques || []).join(', ')}`),
      ``,
      `String References:`,
      ...Object.entries(analysis.string_references || {}).map(([s, refs]) => `  "${s}" → ${refs.map(r => `${r.method}() L${r.line}`).join(', ')}`),
    ]
    copyText(lines.join('\n'))
  }, [analysis])

  const riskBadge = level =>
    level !== 'LOW' ? <ThreatBadge level={level} size="sm" /> : null

  const markBtn = (id, label) => (
    <button
      onClick={() => toggleMark(id)}
      className="tiny-btn"
      style={{
        fontSize: 9, padding: '2px 6px',
        color: markedItems.has(id) ? 'var(--accent-rose)' : 'var(--text-muted)',
        borderColor: markedItems.has(id) ? 'var(--accent-rose)' : undefined,
      }}
    >
      {markedItems.has(id) ? '✓ flagged' : label}
    </button>
  )

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, minHeight: 400 }}>
      <div className="card" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <input
          placeholder="Search classes..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: '100%', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-color)',
            background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
          }}
        />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {filtered.length} of {classes.length} classes
          </span>
          {analysis && (
            <button onClick={() => copyText(JSON.stringify(analysis, null, 2))} style={{
              background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer',
            }}>copy all</button>
          )}
        </div>
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {filtered.map((cls, i) => (
            <button
              key={i}
              onClick={() => setSelectedClass(cls.name)}
              style={{
                textAlign: 'left', padding: '6px 10px', borderRadius: 4, border: 'none',
                fontSize: 12, cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                background: selectedClass === cls.name ? 'var(--accent-cyan-soft)' : 'transparent',
                color: selectedClass === cls.name ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              }}
            >
              {cls.name.split('.').pop()}
              {cls.method_count > 0 && (
                <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                  ({cls.method_count}m)
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="card" style={{ padding: 16, overflow: 'auto' }}>
        {!selectedClass && (
          <div className="empty-state">Select a class to view code analysis</div>
        )}
        {selectedClass && (
          <div style={{
            display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center',
          }}>
            <div style={{
              display: 'flex', gap: 4, padding: 4, borderRadius: 8,
              background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
            }}>
              <button
                onClick={() => setViewMode('analysis')}
                style={{
                  padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
                  fontSize: 12, fontWeight: 600,
                  background: viewMode === 'analysis' ? 'var(--accent-cyan)' : 'transparent',
                  color: viewMode === 'analysis' ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.15s',
                }}
              >Attack Flow</button>
              <button
                onClick={() => { setViewMode('source'); setHighlightString(null) }}
                style={{
                  padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
                  fontSize: 12, fontWeight: 600,
                  background: viewMode === 'source' ? 'var(--accent-cyan)' : 'transparent',
                  color: viewMode === 'source' ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.15s',
                }}
              >Raw Source{highlightString ? ' 🔍' : ''}</button>
            </div>

            {analysis && (
              <div style={{
                display: 'flex', gap: 4, padding: 4, borderRadius: 8,
                background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
              }}>
                <button
                  onClick={() => copyText(JSON.stringify(analysis, null, 2))}
                  style={{
                    padding: '6px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 11, fontWeight: 500, background: 'transparent',
                    color: 'var(--text-secondary)', transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.target.style.color = 'var(--accent-cyan)'}
                  onMouseLeave={e => e.target.style.color = 'var(--text-secondary)'}
                >Copy</button>
                <button
                  onClick={shareAnalysis}
                  style={{
                    padding: '6px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 11, fontWeight: 500, background: 'transparent',
                    color: 'var(--text-secondary)', transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.target.style.color = 'var(--accent-cyan)'}
                  onMouseLeave={e => e.target.style.color = 'var(--text-secondary)'}
                  title="Copy formatted analysis summary"
                >Share</button>
                <button
                  onClick={() => {
                    const el = document.querySelector('.source-code code')
                    if (el) downloadFile(el.textContent || '', `${selectedClass.split('.').pop() || 'class'}.java`)
                  }}
                  style={{
                    padding: '6px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 11, fontWeight: 500, background: 'transparent',
                    color: 'var(--text-secondary)', transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.target.style.color = 'var(--accent-cyan)'}
                  onMouseLeave={e => e.target.style.color = 'var(--text-secondary)'}
                  title="Download source as .java file"
                >Export</button>
              </div>
            )}
          </div>
        )}
        {viewMode === 'source' && selectedClass && (
          <div>
            <div style={{
              display: 'flex', justifyContent: 'flex-end', gap: 8, marginBottom: 12,
            }}>
              <div style={{
                display: 'flex', gap: 4, padding: 4, borderRadius: 8,
                background: 'var(--bg-secondary)', border: '1px solid var(--border-color)',
              }}>
                <button
                  onClick={() => { setHighlightString(null); setViewMode('source') }}
                  style={{
                    padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 11, fontWeight: 500, background: 'transparent',
                    color: highlightString ? 'var(--accent-amber)' : 'var(--text-secondary)',
                    transition: 'all 0.15s',
                  }}
                >
                  {highlightString ? `Highlight: "${highlightString.substring(0, 25)}" ×` : 'No Highlight'}
                </button>
                <button
                  onClick={() => {
                    const el = document.querySelector('.source-code code')
                    if (el) copyText(el.textContent)
                  }}
                  style={{
                    padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontSize: 11, fontWeight: 500, background: 'transparent',
                    color: 'var(--text-secondary)', transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.target.style.color = 'var(--accent-cyan)'}
                  onMouseLeave={e => e.target.style.color = 'var(--text-secondary)'}
                >Copy Source</button>
              </div>
            </div>
            <ClassSourceViewer
              sampleId={sampleId}
              className={selectedClass}
              apiUrl={apiUrl}
              highlight={highlightString}
            />
          </div>
        )}
        {viewMode === 'analysis' && analysisLoading && (
          <div className="empty-state">Loading code analysis...</div>
        )}
        {viewMode === 'analysis' && analysis && (
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, fontFamily: "'JetBrains Mono', monospace" }}>
              {analysis.class_name}
            </div>

            <div style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
              <button
                onClick={() => setFlowView('list')}
                className="tiny-btn"
                style={{ background: flowView === 'list' ? 'var(--accent-cyan)' : 'var(--bg-secondary)', color: flowView === 'list' ? '#fff' : 'var(--text-secondary)' }}
              >List View</button>
              <button
                onClick={() => setFlowView('diagram')}
                className="tiny-btn"
                style={{ background: flowView === 'diagram' ? 'var(--accent-cyan)' : 'var(--bg-secondary)', color: flowView === 'diagram' ? '#fff' : 'var(--text-secondary)' }}
              >Flow Diagram</button>
            </div>

            {analysis.attack_flow?.length > 0 && flowView === 'diagram' && (
              <div style={{ marginBottom: 24, position: 'relative' }}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 12 }}>
                  Attack Flow Diagram
                </div>
                <div style={{ position: 'relative', paddingLeft: 40 }}>
                  {analysis.attack_flow.map((step, i) => {
                    const isLast = i === analysis.attack_flow.length - 1
                    const riskColor = step.risk_level === 'CRITICAL' ? 'var(--accent-rose)'
                      : step.risk_level === 'HIGH' ? 'var(--accent-amber)' : 'var(--text-muted)'
                    return (
                      <div key={i} style={{ position: 'relative', paddingBottom: isLast ? 0 : 24 }}>
                        <div style={{
                          position: 'absolute', left: -32, top: 0, bottom: 0, width: 2,
                          background: isLast ? 'transparent' : riskColor,
                          opacity: 0.4,
                        }} />
                        <div style={{
                          position: 'absolute', left: -38, top: 4, width: 14, height: 14, borderRadius: '50%',
                          background: riskColor, border: '2px solid var(--bg-primary)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 8, fontWeight: 700, color: '#fff', zIndex: 1,
                        }}>{step.step}</div>
                        <div
                          onClick={() => scrollToMethod(step.method)}
                          style={{
                            marginLeft: 8, padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
                            background: step.risk_level === 'CRITICAL' ? 'rgba(244,63,94,0.08)'
                              : step.risk_level === 'HIGH' ? 'rgba(245,158,11,0.08)' : 'var(--bg-secondary)',
                            borderLeft: `3px solid ${riskColor}`,
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600 }}>
                              {step.method}()
                            </span>
                            {riskBadge(step.risk_level)}
                            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", marginLeft: 'auto' }}>
                              L{step.line}
                            </span>
                          </div>
                          {step.description && step.description !== step.method && (
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                              {step.description}
                              {i < analysis.attack_flow.length - 1 && (
                                <span style={{ marginLeft: 8, fontSize: 10 }}>↓</span>
                              )}
                            </div>
                          )}
                          {i < analysis.attack_flow.length - 1 && (
                            <div style={{
                              marginTop: 8, display: 'flex', alignItems: 'center', gap: 4,
                              fontSize: 10, color: riskColor,
                            }}>
                              <span style={{ opacity: 0.6 }}>─────</span>
                              <span>▼ calls next</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {analysis.attack_flow?.length > 0 && flowView === 'list' && (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
                  Attack Flow (list)
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {analysis.attack_flow.map((step, i) => (
                    <div
                      key={i}
                      onClick={() => scrollToMethod(step.method)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
                        padding: '8px 12px', borderRadius: 6,
                        background: step.risk_level === 'CRITICAL' ? 'rgba(244,63,94,0.08)'
                          : step.risk_level === 'HIGH' ? 'rgba(245,158,11,0.08)'
                          : 'var(--bg-secondary)',
                      }}
                    >
                      <span style={{
                        width: 22, height: 22, borderRadius: '50%', display: 'flex',
                        alignItems: 'center', justifyContent: 'center', fontSize: 11,
                        fontWeight: 700, flexShrink: 0,
                        background: step.risk_level === 'CRITICAL' ? 'var(--accent-rose)'
                          : step.risk_level === 'HIGH' ? 'var(--accent-amber)'
                          : 'var(--text-muted)',
                        color: '#fff',
                      }}>{step.step}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>
                          {step.method}()
                          {riskBadge(step.risk_level)}
                        </div>
                        {step.description && step.description !== step.method && step.description !== `${step.method}()` && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{step.description}</div>
                        )}
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                        L{step.line}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>↓</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
              Methods ({analysis.methods?.length || 0})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {analysis.methods?.map((m, i) => {
                const methodKey = `${analysis.class_name}.${m.name}`
                return (
                  <div
                    key={i}
                    ref={el => { if (el) methodRefs.current[m.name] = el }}
                    className="card"
                    style={{
                      padding: '10px 14px', background: 'var(--bg-secondary)',
                      borderLeft: markedItems.has(methodKey) ? '3px solid var(--accent-rose)' : undefined,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                      <div>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600 }}>
                          {m.name}()
                        </span>
                        {riskBadge(m.risk_level)}
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        {markBtn(methodKey, 'flag')}
                        <button
                          onClick={() => copyText(`${m.name}() — ${m.risk_level || 'UNKNOWN'}\nLines: ${m.start_line}–${m.end_line}\nTechniques: ${(m.techniques || []).join(', ')}`)}
                          className="tiny-btn" style={{ fontSize: 9, padding: '2px 6px' }}
                        >copy</button>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                          L{m.start_line}–{m.end_line}
                        </span>
                      </div>
                    </div>

                    {m.techniques?.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8 }}>
                        {m.techniques.map((t, j) => (
                          <span
                            key={j}
                            className="badge"
                            style={{
                              background: 'rgba(245,158,11,0.1)', color: 'var(--accent-amber)',
                              fontSize: 10, cursor: 'default',
                              position: 'relative',
                            }}
                            onMouseEnter={() => setHoveredLine(`${m.name}-${t}`)}
                            onMouseLeave={() => setHoveredLine(null)}
                          >
                            {t.replace(/_/g, ' ')}
                            {hoveredLine === `${m.name}-${t}` && patternDescriptions[t] && (
                              <span style={{
                                position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
                                background: '#1a1f3a', border: '1px solid var(--line)', borderRadius: 6,
                                padding: '6px 10px', fontSize: 10, whiteSpace: 'nowrap', zIndex: 10,
                                color: `var(--accent-${patternDescriptions[t].risk === 'CRITICAL' ? 'rose' : patternDescriptions[t].risk === 'HIGH' ? 'amber' : 'cyan'})`,
                                boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                              }}>
                                {patternDescriptions[t].desc}
                              </span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}

                    {m.suspicious_lines?.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: 12 }}>
                        <div style={{ color: 'var(--accent-rose)', fontWeight: 600, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span>⚠ {m.suspicious_lines.length} suspicious line{m.suspicious_lines.length > 1 ? 's' : ''}</span>
                          {markBtn(`${methodKey}-suspicious`, 'mark all')}
                        </div>
                        {m.suspicious_lines.slice(0, 5).map((sl, j) => {
                          const slKey = `${methodKey}-L${sl.line}`
                          return (
                            <div
                              key={j}
                              style={{
                                padding: '4px 8px', marginTop: 2, borderRadius: 4,
                                background: 'rgba(244,63,94,0.05)', fontSize: 12,
                                fontFamily: "'JetBrains Mono', monospace",
                                color: 'var(--text-secondary)', position: 'relative',
                                borderLeft: markedItems.has(slKey) ? '3px solid var(--accent-rose)' : undefined,
                              }}
                              onMouseEnter={() => setHoveredLine(`${m.name}-${sl.line}`)}
                              onMouseLeave={() => setHoveredLine(null)}
                            >
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span>
                                  <span style={{ color: 'var(--text-muted)' }}>L{sl.line}: </span>
                                  {sl.code?.substring(0, 100)}
                                </span>
                                <div style={{ display: 'flex', gap: 4 }}>
                                  {markBtn(slKey, '⚠')}
                                  <button
                                    onClick={() => navigateToSource(sl.code?.substring(0, 40) || '')}
                                    className="tiny-btn" style={{ fontSize: 8, padding: '1px 4px' }}
                                    title="View in source"
                                  >🔍</button>
                                </div>
                              </div>
                              {hoveredLine === `${m.name}-${sl.line}` && (
                                <span style={{
                                  position: 'absolute', top: '100%', left: 0, marginTop: 4,
                                  background: '#1a1f3a', border: '1px solid var(--line)', borderRadius: 6,
                                  padding: '8px 12px', fontSize: 11, zIndex: 10, minWidth: 250,
                                  color: 'var(--ink)', lineHeight: 1.5,
                                  boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                                }}>
                                  <div style={{ fontWeight: 600, marginBottom: 4, color: 'var(--accent-rose)' }}>
                                    Pattern: {sl.pattern?.replace(/_/g, ' ') || 'suspicious'}
                                    {patternDescriptions[sl.pattern] && (
                                      <span style={{ fontWeight: 400, color: `var(--accent-${patternDescriptions[sl.pattern].risk === 'CRITICAL' ? 'rose' : 'amber'})`, marginLeft: 8 }}>
                                        · {patternDescriptions[sl.pattern].risk} risk
                                      </span>
                                    )}
                                  </div>
                                  <div style={{ color: 'var(--text-secondary)' }}>
                                    {patternDescriptions[sl.pattern]?.desc || sl.description || 'Suspicious code pattern detected'}
                                  </div>
                                </span>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )}

                    {m.calls?.length > 0 && (
                      <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {m.calls.map((c, j) => (
                          <span
                            key={j}
                            className="badge neutral"
                            style={{ fontSize: 10, cursor: 'pointer' }}
                            onClick={() => scrollToMethod(c.target)}
                          >
                            → {c.target}()
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {analysis.string_references && Object.keys(analysis.string_references).length > 0 && (
              <div style={{ marginTop: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
                    String References ({Object.keys(analysis.string_references).length})
                  </div>
                  <button
                    onClick={() => copyText(Object.entries(analysis.string_references).map(([s, refs]) => `"${s}" → ${refs.map(r => `${r.method}() L${r.line}`).join(', ')}`).join('\n'))}
                    className="tiny-btn" style={{ fontSize: 9, padding: '2px 6px' }}
                  >copy</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 480, overflowY: 'auto', paddingRight: 4 }}>
                  {Object.entries(analysis.string_references).map(([str, refs], i) => {
                    const strKey = `str:${str}`
                    return (
                      <div key={i} style={{
                        padding: '6px 10px', borderRadius: 4, fontSize: 12,
                        background: 'var(--bg-secondary)',
                        fontFamily: "'JetBrains Mono', monospace",
                        borderLeft: markedItems.has(strKey) ? '3px solid var(--accent-rose)' : undefined,
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span>
                            <span
                              style={{ color: 'var(--accent-amber)', cursor: 'pointer', textDecoration: 'underline 1px dotted' }}
                              onClick={() => navigateToSource(str)}
                              title="Find in source"
                            >
                              &quot;{str.substring(0, 60)}&quot;
                            </span>
                            <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
                              used in {refs.length} location{refs.length > 1 ? 's' : ''}
                            </span>
                          </span>
                          <div style={{ display: 'flex', gap: 4 }}>
                            {markBtn(strKey, 'mark')}
                            <button
                              onClick={() => navigateToSource(str)}
                              className="tiny-btn" style={{ fontSize: 8, padding: '1px 4px' }}
                              title="Find in source code"
                            >🔍</button>
                          </div>
                        </div>
                        <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {refs.map((r, ri) => (
                            <span
                              key={ri}
                              className="badge neutral"
                              style={{ fontSize: 9, cursor: 'pointer' }}
                              onClick={() => scrollToMethod(r.method)}
                              title={`Click to scroll to ${r.method}()`}
                            >
                              {r.method}() L{r.line}
                            </span>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

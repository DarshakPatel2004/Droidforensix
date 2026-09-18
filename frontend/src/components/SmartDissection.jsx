import { useState, useEffect, useMemo, useCallback } from 'react'
import '../styles/SmartDissection.css'

const UNWANTED_PATTERNS = [
  /android\.support\..*/,
  /androidx\..*\.R\$/,
  /androidx\..*\.BuildConfig/,
  /com\.android\.internal\..*/,
  /android\.view\.View\$/,
  /com\.google\.android\..*BuildConfig/,
  /\$\d+/,
  /\$StaticInjectorHolder/,
  /\$Lambda/,
  /kotlin\.jvm\.JvmStatic/,
  /kotlin\.jvm\.JvmOverloads/,
  /kotlin\.Metadata/,
  /super\(\)/,
  /onCreate\(\)/,
  /onDestroy\(\)/,
  /getIntent\(\)/,
  /setContentView\(/,
  /findViewById\(/,
]

const SUSPICIOUS_KEYWORDS = [
  'invoke', 'Cipher', 'ClassLoader', 'reflect', 'DexClassLoader',
  'Runtime.exec', 'ProcessBuilder', 'HttpURLConnection', 'Base64',
  'decode', 'encrypt', 'socket', 'intent', 'permission',
]

const KEYWORD_COLORS = {
  'Cipher': 'violet', 'ClassLoader': 'cyan', 'DexClassLoader': 'cyan',
  'reflect': 'amber', 'Runtime.exec': 'rose', 'ProcessBuilder': 'rose',
  'HttpURLConnection': 'emerald', 'socket': 'emerald', 'Base64': 'amber',
  'decode': 'amber', 'encrypt': 'violet', 'permission': 'cyan',
}

const METHODS_PREVIEW_LIMIT = 20

export default function SmartDissection({ sample, apiUrl, onSelectClass }) {
  const [dissectionData, setDissectionData] = useState(null)
  const [obfuscationData, setObfuscationData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [expandAll, setExpandAll] = useState(false)
  const [error, setError] = useState(null)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  const fetchDissection = useCallback(async (isCancelled) => {
    if (!sampleId) return
    try {
      setLoading(true)
      const [classesRes, obfRes] = await Promise.all([
        fetch(`${apiUrl}/api/sample/${sampleId}/dissection/classes`),
        fetch(`${apiUrl}/api/sample/${sampleId}/obfuscation`),
      ])
      if (isCancelled && isCancelled()) return
      if (!classesRes.ok) throw new Error(`HTTP ${classesRes.status}`)
      const classesData = await classesRes.json()
      const obfData = obfRes.ok ? await obfRes.json() : null
      setDissectionData(classesData)
      setObfuscationData(obfData)
      setError(null)
    } catch (err) {
      setError('Failed to load dissection: ' + err.message)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [sampleId, apiUrl])

  useEffect(() => {
    let cancelled = false
    fetchDissection(() => cancelled) // eslint-disable-line react-hooks/set-state-in-effect
    return () => { cancelled = true }
  }, [sampleId, apiUrl, fetchDissection])

  const allClasses = useMemo(() => dissectionData?.classes || [], [dissectionData?.classes])

  const obfuscatedClasses = useMemo(() => {
    const names = new Set()
    const techniques = obfuscationData?.techniques || []
    techniques.forEach(tech => {
      (tech.items || []).forEach(item => {
        if (item.class) names.add(item.class)
      })
    })
    return names
  }, [obfuscationData])

  const isObfuscatedClass = useCallback((cls) => obfuscatedClasses.has(cls.name), [obfuscatedClasses])

  const filteredClasses = useMemo(() => {
    let classes = allClasses
    if (filter === 'malicious') {
      classes = classes.filter(cls => isSuspiciousClass(cls))
    } else if (filter === 'obfuscated') {
      classes = classes.filter(cls => isObfuscatedClass(cls))
    }

    if (search.trim()) {
      const q = search.toLowerCase()
      classes = classes.filter(cls =>
        cls.name.toLowerCase().includes(q) ||
        (cls.methods || []).some(m => m.name.toLowerCase().includes(q)) ||
        (cls.network_calls || []).some(c => c.toLowerCase().includes(q))
      )
    }

    return classes
  }, [allClasses, filter, search, isObfuscatedClass])

  const suspiciousCount = allClasses.filter(isSuspiciousClass).length
  const obfuscatedCount = allClasses.filter(isObfuscatedClass).length

  if (loading) {
    return (
      <div className="state-container modern-empty">
        <div className="analysis-loading-spinner"></div>
        <h3 className="state-title">Loading Code Dissection</h3>
        <p className="state-description">Fetching decompiled classes and suspicious method analysis...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="state-container error-container modern-empty">
        <span className="state-icon">⚠</span>
        <h3 className="state-title">Dissection Error</h3>
        <p className="state-description">{error}</p>
        <button className="filter-button filter-cyan" style={{ marginTop: '1rem' }} onClick={() => { setError(null); fetchDissection() }}>
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="dissection">
      <div className="dissection-toolbar card">
        <div className="dissection-filters">
          <FilterButton
            active={filter === 'malicious'}
            onClick={() => setFilter('malicious')}
            label="Suspicious"
            count={suspiciousCount}
            color="rose"
          />
          <FilterButton
            active={filter === 'obfuscated'}
            onClick={() => setFilter('obfuscated')}
            label="Obfuscated"
            count={obfuscatedCount}
            color="violet"
          />
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All Classes"
            count={allClasses.length}
            color="cyan"
          />
        </div>
        <div className="dissection-toolbar-right">
          <button
            className={`expand-all-button ${expandAll ? 'active' : ''}`}
            onClick={() => setExpandAll(v => !v)}
            title={expandAll ? 'Collapse all method bodies' : 'Expand all method bodies'}
          >
            {expandAll ? 'Collapse code' : 'Expand code'}
          </button>
          <div className="dissection-search">
            <span className="search-icon">🔎</span>
            <input
              type="text"
              placeholder="Search class or method name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="dissection-results card">
        <div className="dissection-results-header">
          <span className="section-title">
            {filter === 'malicious' ? 'Suspicious Classes' : filter === 'obfuscated' ? 'Obfuscated Classes' : 'All Classes'}
          </span>
          <span className="results-count">{filteredClasses.length} result(s)</span>
        </div>

        {filteredClasses.length === 0 ? (
          <div className="dissection-empty">
            <span className="empty-icon">🔍</span>
            <p>No matching classes found</p>
            {filter === 'malicious' && allClasses.length > 0 && (
              <button
                className="filter-button filter-cyan"
                onClick={() => setFilter('all')}
              >
                Show all {allClasses.length} decompiled classes
              </button>
            )}
          </div>
        ) : (
          <div className="classes-list">
            {filteredClasses.map((cls, idx) => (
              <ClassCard
                key={idx}
                classData={cls}
                isObfuscated={isObfuscatedClass(cls)}
                expandAll={expandAll}
                onSelectClass={onSelectClass}
                sampleId={sampleId}
                apiUrl={apiUrl}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function FilterButton({ active, onClick, label, count, color }) {
  return (
    <button
      className={`filter-button filter-${color} ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      <span>{label}</span>
      <span className="filter-count">{count}</span>
    </button>
  )
}

function ClassCard({ classData, isObfuscated, expandAll, onSelectClass, sampleId, apiUrl }) {
  const [expanded, setExpanded] = useState(false)
  const [showAllMethods, setShowAllMethods] = useState(false)
  const [methods, setMethods] = useState(null)
  const [methodsLoading, setMethodsLoading] = useState(false)
  const [methodsLoadError, setMethodsLoadError] = useState(null)

  // Lazy-load method bodies when first expanded
  useEffect(() => {
    if (!expanded || methods !== null || methodsLoading) return
    setMethodsLoading(true) // eslint-disable-line react-hooks/set-state-in-effect
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/class-methods/${encodeURIComponent(classData.name)}`)
      .then(r => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then(data => {
        const sorted = (data.methods || []).slice().sort((a, b) => {
          return methodSuspicionScore(b) - methodSuspicionScore(a)
        })
        setMethods(sorted)
      })
      .catch(err => {
        setMethodsLoadError(String(err))
        setMethods([])
      })
      .finally(() => setMethodsLoading(false))
  }, [expanded, methods, methodsLoading, sampleId, apiUrl, classData.name])  

  const methodCount = classData.method_count || (classData.methods || []).length
  const methodNames = classData.method_names || (classData.methods || []).map(m => m.name)
  const suspiciousMethodCount = methods
    ? methods.filter(m => methodSuspicionScore(m) > 0).length
    : methodNames.filter(n => SUSPICIOUS_KEYWORDS.some(kw => n.toLowerCase().includes(kw.toLowerCase()))).length
  const isSuspicious = suspiciousMethodCount > 0 || hasNetworkCall(classData)
  const displayMethods = methods && (showAllMethods ? methods : methods.slice(0, METHODS_PREVIEW_LIMIT))

  return (
    <div className={`class-card ${isSuspicious ? 'suspicious' : ''} ${isObfuscated ? 'obfuscated' : ''}`}>
      <div className="class-header" onClick={() => setExpanded(!expanded)}>
        <div className="class-header-left">
          <span className="class-expand">{expanded ? '▼' : '▶'}</span>
          <span className="class-name text-mono" title={classData.name}>{classData.name}</span>
        </div>
        <div className="class-header-right">
          {isObfuscated && <span className="class-badge badge-violet">Obfuscated</span>}
          {isSuspicious && <span className="class-badge badge-high">Suspicious</span>}
          {suspiciousMethodCount > 0 && (
            <span className="class-badge badge-amber">{suspiciousMethodCount} hit(s)</span>
          )}
          {(classData.network_calls || []).length > 0 && (
            <span className="class-badge badge-cyan">{classData.network_calls.length} network</span>
          )}
          {onSelectClass && (
            <button
              className="class-badge view-source-btn"
              onClick={(e) => {
                e.stopPropagation()
                onSelectClass(classData.name)
              }}
              title="View decompiled source"
            >
              View source
            </button>
          )}
          <span className="class-badge badge-slate">{methodCount} method(s)</span>
        </div>
      </div>

      {expanded && (
        <div className="class-body">
          <div className="class-section">
            <div className="class-section-header">
              <h4 className="section-title">Methods</h4>
              <span className="class-section-meta">{methods ? methods.length : methodCount} total</span>
            </div>
            {methodsLoading ? (
              <div className="llm-shimmer" style={{ padding: '1rem' }}>
                <div className="shimmer-bar shimmer-bar-long" />
                <div className="shimmer-bar shimmer-bar-medium" />
              </div>
            ) : displayMethods && displayMethods.length > 0 ? (
              <div className="methods-list">
                {displayMethods.map((method, idx) => (
                  <MethodCard
                    key={idx}
                    method={method}
                    expandAll={expandAll}
                    sampleId={sampleId}
                    className={classData.name}
                    apiUrl={apiUrl}
                  />
                ))}
                {methods && methods.length > METHODS_PREVIEW_LIMIT && (
                  <button
                    className="show-more-methods"
                    onClick={() => setShowAllMethods(v => !v)}
                  >
                    {showAllMethods ? `Show first ${METHODS_PREVIEW_LIMIT} methods` : `Show ${methods.length - METHODS_PREVIEW_LIMIT} more methods`}
                  </button>
                )}
              </div>
            ) : methodsLoadError ? (
              <div className="methods-error">
                <p className="class-empty">Failed to load methods: {methodsLoadError}</p>
                <button className="filter-button filter-cyan" onClick={() => { setMethodsLoadError(null); setMethodsLoading(true); setMethods(null); }}>
                  Retry
                </button>
              </div>
            ) : (
              <p className="class-empty">No methods available</p>
            )}
          </div>

          <div className="class-section">
            <h4 className="section-title">Network Activity</h4>
            {classData.network_calls && classData.network_calls.length > 0 ? (
              <div className="network-calls">
                {classData.network_calls.map((call, idx) => (
                  <div key={idx} className="network-call-chip text-mono" title={call}>{call}</div>
                ))}
              </div>
            ) : (
              <p className="class-empty">No network activity detected</p>
            )}
          </div>

          <div className="class-section">
            <h4 className="section-title">Permissions Used</h4>
            {classData.permissions_used && classData.permissions_used.length > 0 ? (
              <div className="permissions-cloud">
                {classData.permissions_used.map((perm, idx) => (
                  <span key={idx} className="permission-mini">{perm.split('.').pop()}</span>
                ))}
              </div>
            ) : (
              <p className="class-empty">No permission checks detected</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Per-line annotation type → colour class mapping
const ANNOTATION_COLORS = {
  reflection:       'annotation-amber',
  dynamic_loading:  'annotation-cyan',
  crypto:           'annotation-violet',
  encoding:         'annotation-amber',
  command_exec:     'annotation-rose',
  network:          'annotation-emerald',
  permissions:      'annotation-cyan',
}

const THREAT_TYPE_LABELS = {
  reflection:       'Reflection',
  dynamic_loading:  'Dynamic Loading',
  crypto:           'Crypto',
  network:          'Network',
  command_exec:     'Command Exec',
  persistence:      'Persistence',
  encoding:         'Encoding',
  permissions:      'Permissions',
  benign:           'Benign',
  unknown:          'Unknown',
}

function MethodCard({ method, expandAll, sampleId, className, apiUrl }) {
  const [expanded, setExpanded] = useState(expandAll)
  const [annotation, setAnnotation] = useState(null)
  const [annotationError, setAnnotationError] = useState(null)
  const [annotating, setAnnotating] = useState(false)

  useEffect(() => {
    setExpanded(expandAll) // eslint-disable-line react-hooks/set-state-in-effect
  }, [expandAll])

  // Fire explain-method when first expanded
  useEffect(() => {
    if (!expanded || annotation || annotating) return
    if (!sampleId || apiUrl === undefined || apiUrl === null || !method.body) return

    const flags = SUSPICIOUS_KEYWORDS.filter(kw =>
      method.name.toLowerCase().includes(kw.toLowerCase()) ||
      (method.body && method.body.toLowerCase().includes(kw.toLowerCase()))
    )

    setAnnotating(true) // eslint-disable-line react-hooks/set-state-in-effect
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/explain-method`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        class_name: className,
        method_name: method.name,
        method_code: method.body,
        flags,
      }),
    })
      .then(r => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then(data => { if (data) setAnnotation(data) })
      .catch(err => setAnnotationError(String(err)))
      .finally(() => setAnnotating(false))
  }, [expanded, sampleId, apiUrl, className, method.name, method.body]) // eslint-disable-line react-hooks/exhaustive-deps

  const matchedKeyword = SUSPICIOUS_KEYWORDS.find(kw =>
    method.name.toLowerCase().includes(kw.toLowerCase()) ||
    (method.body && method.body.toLowerCase().includes(kw.toLowerCase()))
  )

  const bodyLines = method.body ? method.body.split('\n').filter(l => l.trim() !== '') : []
  const previewLines = bodyLines.slice(0, 3)

  return (
    <div className={`method-card ${matchedKeyword ? 'method-suspicious' : ''}`}>
      <div className="method-header" onClick={() => setExpanded(!expanded)}>
        <div className="method-header-left">
          <span className="method-expand">{expanded ? '▼' : '▶'}</span>
          <span className="method-name text-mono">{method.name}</span>
        </div>
        <div className="method-header-right">
          {bodyLines.length > 0 && (
            <span className="method-line-count">{bodyLines.length} lines</span>
          )}
          {matchedKeyword && (
            <span className={`method-keyword keyword-${KEYWORD_COLORS[matchedKeyword] || 'rose'}`}>
              {matchedKeyword}
            </span>
          )}
        </div>
      </div>

      {method.body && (
        <div className={`method-body ${expanded ? 'expanded' : 'preview'}`}>

          {/* LLM summary block — only when expanded */}
          {expanded && (
            <div className="method-llm-summary">
              {annotating ? (
                <div className="llm-shimmer">
                  <div className="shimmer-bar shimmer-bar-long" />
                  <div className="shimmer-bar shimmer-bar-medium" />
                </div>
              ) : annotation?.llm ? (
                <div className="llm-result">
                  <div className="llm-result-header">
                    <span className="llm-icon">🧠</span>
                    <span className="llm-label">AI Analysis</span>
                    {annotation.llm.threat_type && annotation.llm.threat_type !== 'unknown' && (
                      <span className={`llm-threat-badge threat-${annotation.llm.threat_type}`}>
                        {THREAT_TYPE_LABELS[annotation.llm.threat_type] || annotation.llm.threat_type}
                      </span>
                    )}
                    {annotation.llm.confidence != null && (
                      <span className="llm-confidence">
                        {Math.round(annotation.llm.confidence * 100)}% confidence
                      </span>
                    )}
                  </div>
                  <p className="llm-summary-text">{annotation.llm.summary}</p>
                </div>
              ) : annotationError ? (
                <div className="annotation-error">
                  AI analysis unavailable: {annotationError}
                </div>
              ) : null}
            </div>
          )}

          {expanded ? (
            <CodeHighlight
              code={method.body}
              lineAnnotations={annotation?.line_annotations || {}}
            />
          ) : (
            <div className="method-preview">
              <CodeHighlight code={previewLines.join('\n')} lineAnnotations={{}} />
              {bodyLines.length > 3 && (
                <button className="preview-expand" onClick={() => setExpanded(true)}>
                  Show full code ({bodyLines.length - 3} more lines)
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function CodeHighlight({ code, lineAnnotations = {} }) {
  const lines = code.split('\n')
  return (
    <pre className="code-block">
      {lines.map((line, idx) => {
        const isSuspicious = SUSPICIOUS_KEYWORDS.some(kw => line.toLowerCase().includes(kw.toLowerCase()))
        const ann = lineAnnotations[idx]
        return (
          <div key={idx} className={`code-line ${isSuspicious ? 'suspicious-line' : ''}`}>
            <span className="line-num">{idx + 1}</span>
            <code>{highlightSyntax(line)}</code>
            {ann && (
              <span className={`line-annotation ${ANNOTATION_COLORS[ann.type] || 'annotation-amber'}`}>
                ← {ann.label}
              </span>
            )}
          </div>
        )
      })}
    </pre>
  )
}

function highlightSyntax(line) {
  let highlighted = line
  SUSPICIOUS_KEYWORDS.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi')
    highlighted = highlighted.replace(regex, `<span class="code-keyword">${keyword}</span>`)
  })
  return <code dangerouslySetInnerHTML={{ __html: highlighted }} />
}

function methodSuspicionScore(method) {
  let score = 0
  if (!method.body && !method.name) return score
  const nameLower = (method.name || '').toLowerCase()
  SUSPICIOUS_KEYWORDS.forEach(kw => {
    if (nameLower.includes(kw.toLowerCase())) score += 2
    if (method.body) {
      const bodyLower = method.body.toLowerCase()
      if (bodyLower.includes(kw.toLowerCase())) score += 1
    }
  })
  return score
}

function isSuspiciousClass(cls) {
  if (UNWANTED_PATTERNS.some(pattern => pattern.test(cls.name))) {
    return false
  }
  // Lightweight check using method_names (no body needed)
  const methodNames = cls.method_names || []
  if (methodNames.some(name =>
    SUSPICIOUS_KEYWORDS.some(kw => name.toLowerCase().includes(kw.toLowerCase()))
  )) {
    return true
  }
  return hasNetworkCall(cls)
}

function hasNetworkCall(cls) {
  const networkPatterns = ['HttpURLConnection', 'socket', 'URLConnection', 'okhttp', 'retrofit']
  // Check network_calls array first (available in lightweight payload)
  if ((cls.network_calls || []).length > 0) return true
  // Fallback: check method names
  const methodNames = cls.method_names || []
  return networkPatterns.some(pattern =>
    methodNames.some(name => name.toLowerCase().includes(pattern.toLowerCase()))
  )
}

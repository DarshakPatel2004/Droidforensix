import { useState, useEffect, useMemo, useCallback, memo } from 'react'
import './AnalysisView.css'
import ObfuscationView from './ObfuscationView'
import ManifestView from './ManifestView'
import FamilySignalsCard from './FamilySignalsCard'
import ThreatSynthesisPanel from './ThreatSynthesisPanel'

/**
 * Format seconds into human-readable duration.
 * e.g., 65 -> "1m 5s", 3661 -> "1h 1m 1s"
 */
export function riskLevelBadgeClass(level) {
  const map = { critical: 'rose', high: 'rose', medium: 'amber', low: 'emerald', none: 'slate', unknown: 'slate' }
  return `badge-${map[level] || 'slate'}`
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—'
  if (seconds === 0) return '0s'

  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)

  const parts = []
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  if (s > 0) parts.push(`${s}s`)

  return parts.join(' ')
}

/**
 * Memoized KPI Card: prevents re-render unless its specific metrics change.
 */
const KPICard = memo(({ label, value, icon, color }) => (
  <div className="kpi-card" style={{ borderTopColor: color }}>
    <div className="kpi-icon" style={{ color }}>{icon}</div>
    <div className="kpi-content">
      <p className="kpi-label">{label}</p>
      <p className="kpi-value">{value}</p>
    </div>
  </div>
))

KPICard.displayName = 'KPICard'

/**
 * Memoized Loading State: shows progress bar, ETA, and live metrics.
 */
const LoadingState = memo(({ analysisState }) => {
  const { progress, eta } = analysisState

  return (
    <div className="analysis-loading">
      <div className="loading-radar">
        <svg viewBox="0 0 100 100" className="hex-radar">
          <defs>
            <linearGradient id="hex-sweep" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="transparent" />
              <stop offset="45%" stopColor="var(--accent-cyan)" stopOpacity="0.08" />
              <stop offset="50%" stopColor="var(--accent-cyan)" stopOpacity="0.4" />
              <stop offset="55%" stopColor="var(--accent-cyan)" stopOpacity="0.08" />
              <stop offset="100%" stopColor="transparent" />
            </linearGradient>
          </defs>

          <polygon points="50 3, 93 26.5, 93 73.5, 50 97, 7 73.5, 7 26.5"
            fill="none" stroke="var(--accent-cyan)" strokeWidth="1" opacity="0.2" className="hex-ripple" />

          <polygon points="50 18, 78 33, 78 67, 50 82, 22 67, 22 33"
            fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5" opacity="0.35" className="hex-ripple" style={{ animationDelay: '0.6s' }} />

          <polygon points="50 30, 65 39, 65 61, 50 70, 35 61, 35 39"
            fill="none" stroke="var(--accent-cyan)" strokeWidth="2" opacity="0.55" className="hex-ripple" style={{ animationDelay: '1.2s' }} />

          <polygon points="50 3, 93 26.5, 93 73.5, 50 97, 7 73.5, 7 26.5"
            fill="url(#hex-sweep)" className="scan-sweep-hex" />

          <circle cx="50" cy="50" r="5" fill="var(--accent-cyan)" className="center-pulse" />
        </svg>
      </div>

      <h2>Static Analysis Running</h2>
      <p className="loading-status">
        {eta !== null && eta > 0
          ? `ETA: ${formatDuration(eta)}`
          : 'Preparing analysis environment...'}
      </p>

      <div className="progress-container">
        <div className="progress-bar-wrapper">
          <div
            className="progress-bar-fill"
            style={{ width: `${progress || 0}%` }}
          />
        </div>
        <span className="progress-percent">{Math.round(progress || 0)}%</span>
      </div>

      <div className="kpi-strip">
        <KPICard
          label="Encodings"
          value={analysisState.metrics?.encoding_count || 0}
          icon="🔐"
          color="var(--accent-amber)"
        />
        <KPICard
          label="Payloads"
          value={analysisState.metrics?.payload_count || 0}
          icon="💾"
          color="var(--accent-rose)"
        />
        <KPICard
          label="C2 Endpoints"
          value={analysisState.metrics?.c2_count || 0}
          icon="🌐"
          color="var(--accent-emerald)"
        />
        <KPICard
          label="Threat Chains"
          value={analysisState.metrics?.threat_chain_count || 0}
          icon="⛓️"
          color="var(--accent-violet)"
        />
      </div>
    </div>
  )
})

LoadingState.displayName = 'LoadingState'

/**
 * Memoized Result View: shown when analysis completes.
 * Handles loading full result JSON and rendering tabs.
 */
const ResultView = memo(({ analysisState, apiUrl, sample }) => {
  const [fullResult, setFullResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeResultTab, setActiveResultTab] = useState('overview')

  const sampleId = analysisState.sampleId

  // Fetch full result once analysis completes.
  // Prefer SHA-256 from the sample prop (backend key) over analysisState.sampleId
  // for robustness against any ID type inconsistency.
  const effectiveSampleId = sample?.sha256 || sampleId

  useEffect(() => {
    if (!effectiveSampleId) return

    let cancelled = false

    const fetchResult = async () => {
      try {
        setLoading(true)
        setError(null)

        const response = await fetch(`${apiUrl}/api/sample/${effectiveSampleId}`)

        if (response.status === 404) {
          setError('Analysis results not yet available. Pipeline may still be processing.')
          return
        }

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`)
        }

        const data = await response.json()
        if (!data) {
          throw new Error('Empty response from server')
        }

        if (!cancelled) {
          setFullResult(data)
          setError(null)
        }
      } catch (err) {
        console.error('Result fetch failed:', err)
        if (!cancelled) {
          setError(err.message || 'Failed to fetch analysis results')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    // Small delay to allow backend to write pipeline_result.json
    const timer = setTimeout(fetchResult, 500)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [effectiveSampleId, apiUrl])

  if (loading) {
    return (
      <div className="result-loading text-center p-10 text-lg">
        <div className="mb-4">⏳</div>
        <p>Loading analysis results...</p>
        <p className="text-sm text-muted mt-2">
          This may take a moment while the backend processes your analysis.
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="result-error p-8 bg-secondary rounded-sm border-rose mt-4">
        <div className="text-3xl mb-3">⚠️</div>
        <h3 className="heading-sm mb-2">Analysis Results Unavailable</h3>
        <p className="text-secondary mb-3">
          {error}
        </p>
        <p className="text-sm text-muted">
          <strong>Troubleshooting:</strong>
        </p>
        <ul className="text-sm text-muted mt-2" style={{ paddingLeft: '20px' }}>
          <li>Check that the analysis completed successfully (backend logs)</li>
          <li>Verify the backend is running on {apiUrl}</li>
          <li>Ensure pipeline_result.json was generated in the work directory</li>
          <li>Try uploading a different APK to test the pipeline</li>
        </ul>
      </div>
    )
  }

  if (!fullResult) {
    return (
      <div className="result-error">
        <p>No analysis data available.</p>
      </div>
    )
  }

  const metadata = fullResult.metadata || {}
  const verdict = analysisState.verdictData

  return (
    <div className="analysis-result">
      {/* Hero Section */}
      <div className="result-hero">
        <div className="hero-accent" style={{ backgroundColor: verdict?.verdict === 'malware' ? 'var(--accent-rose)' : 'var(--accent-emerald)' }} />
        <div className="hero-content">
          <h1>{metadata.package_name || 'Unknown Package'}</h1>
          <div className="hero-badges">
            <span className="badge badge-cyan">{metadata.sha256?.slice(0, 16)}...</span>
            <span className="badge badge-slate">{(metadata.file_size_bytes / 1024 / 1024).toFixed(2)} MB</span>
          </div>
        </div>

        <div className="result-metrics">
          <div className="metric">
            <span className="metric-label">Verdict</span>
            <span className={`metric-value badge badge-${verdict?.verdict === 'malware' ? 'rose' : 'emerald'}`}>
              {verdict?.verdict?.toUpperCase() || '—'}
            </span>
          </div>
          <div className="metric">
            <span className="metric-label">Risk Score</span>
            <span className="metric-value">{verdict?.riskScore || 0} / 100</span>
          </div>
          <div className="metric">
            <span className="metric-label">Analysis Time</span>
            <span className="metric-value">{formatDuration(verdict?.totalDuration)}</span>
          </div>
          {fullResult?.threat_synthesis && (
            <div className="metric">
              <span className="metric-label">Zero-Day Risk</span>
              <span className="metric-value">
                {fullResult.threat_synthesis.zero_day_risk_score ?? 0}
                {' '}
                <span className={`badge badge-xs align-middle ${riskLevelBadgeClass(fullResult.threat_synthesis.risk_level)}`}>
                  {fullResult.threat_synthesis.risk_level?.toUpperCase() || 'NONE'}
                </span>
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="result-tabs">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'secrets', label: 'Secrets' },
          { id: 'llm', label: 'LLM Summary' },
          { id: 'dissection-summary', label: 'Dissection Summary' },
          { id: 'obfuscation', label: 'Obfuscation' },
          { id: 'chains', label: 'Threat Chains' },
          { id: 'synthesis', label: 'Threat Synthesis' },
          { id: 'manifest', label: 'Manifest' },
        ].map(tab => (
          <button
            key={tab.id}
            className={`tab-button ${activeResultTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveResultTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeResultTab === 'overview' && (
          <OverviewTab result={fullResult} sampleId={effectiveSampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'secrets' && (
          <SecretsTab result={fullResult} />
        )}
        {activeResultTab === 'llm' && (
          <LLMSummaryTab result={fullResult} />
        )}
        {activeResultTab === 'dissection-summary' && (
          <DissectionSummaryTab sampleId={effectiveSampleId} apiUrl={apiUrl} />
        )}
        {activeResultTab === 'obfuscation' && (
          <ObfuscationView sample={sample} apiUrl={apiUrl} result={fullResult} />
        )}
        {activeResultTab === 'synthesis' && (
          <ThreatSynthesisPanel synthesis={fullResult?.threat_synthesis} />
        )}
        {activeResultTab === 'chains' && (
          <ChainsTab result={fullResult} apiUrl={apiUrl} sampleId={effectiveSampleId} />
        )}
        {activeResultTab === 'manifest' && (
          <ManifestView sample={sample} apiUrl={apiUrl} />
        )}
      </div>
    </div>
  )
})

ResultView.displayName = 'ResultView'

/**
 * Overview Tab Content
 */
const OverviewTab = memo(({ result, sampleId, apiUrl }) => (
  <div className="tab-panel">
    <div className="card">
      <h3 className="heading-sm">Assessment Summary</h3>
      <p>{result?.llm_assessment?.narrative || 'No narrative available.'}</p>
    </div>

    <div className="card">
        <h3 className="heading-sm">Recommended Actions</h3>
      <ul className="detail-list">
        {(result?.llm_assessment?.recommended_actions || []).map((action, i) => (
          <li key={i}>{action}</li>
        ))}
      </ul>
    </div>

    <FamilySignalsCard sampleId={sampleId} apiUrl={apiUrl} />

    <div className="metrics-grid">
      <div className="card">
        <h4 className="heading-sm">Strings</h4>
        <p className="metric-value">{result?.extraction?.total_strings_extracted || 0}</p>
      </div>
      <div className="card">
        <h4 className="heading-sm">Classes</h4>
        <p className="metric-value">{result?.extraction?.decompiled_classes || 0}</p>
      </div>
      <div className="card">
        <h4 className="heading-sm">C2 Endpoints</h4>
        <p className="metric-value">{(result?.c2_infrastructure || []).length}</p>
      </div>
      <div className="card">
        <h4 className="heading-sm">Threat Chains</h4>
        <p className="metric-value">{(result?.threat_chains || []).length}</p>
      </div>
      <div className="card">
        <h4 className="heading-sm">Secrets</h4>
        <p className="metric-value">{result?.secret_risk?.total_secrets || 0}</p>
        <p className="metric-sub text-sm text-muted">
          {result?.secret_risk?.severity || 'none'}
        </p>
      </div>
    </div>
  </div>
))

OverviewTab.displayName = 'OverviewTab'

/**
 * LLM Summary Tab
 */
const LLMSummaryTab = memo(({ result }) => {
  const llm = result?.llm_assessment || {}
  const narrative = llm.narrative || 'No LLM analysis available.'
  const methods = llm.suspicious_methods || []
  const actions = llm.recommended_actions || []

  return (
    <div className="tab-panel">
      <div className="card">
        <h3 className="heading-sm">LLM Analysis Narrative</h3>
        <div className="narrative-block">
          {narrative}
        </div>
      </div>

      {methods.length > 0 && (
        <div className="card">
          <h3 className="heading-sm">
            Suspicious Methods ({methods.length})
          </h3>
          <div className="scroll-400">
              {methods.map((method, i) => (
              <div key={i} className="code-block">
                <div className="code-block-header">
                  {method.method_name || method}
                </div>
                {method.reason && (
                  <div className="code-block-detail">
                    {method.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
          {methods.length > 10 && (
            <p className="more-link">… and {methods.length - 10} more</p>
          )}
        </div>
      )}

      {actions.length > 0 && (
        <div className="card">
      <h3 className="heading-sm">Recommended Actions</h3>
          <ul className="detail-list">
            {actions.map((action, i) => (
              <li key={i}>{action}</li>
            ))}
          </ul>
        </div>
      )}

      {methods.length === 0 && actions.length === 0 && !narrative && (
        <div className="empty-state">
          <p>No LLM analysis data available yet.</p>
        </div>
      )}
    </div>
  )
})

LLMSummaryTab.displayName = 'LLMSummaryTab'

/**
 * Dissection Summary Tab — real-time LLM threat assessment from dissection data
 * FIXED: Sanitizes response to prevent "Objects are not valid as React child" error
 */
const DissectionSummaryTab = memo(({ sampleId, apiUrl }) => {
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!sampleId) return
    let cancelled = false

    const fetchSummary = async () => {
      try {
        setLoading(true)
        setError(null)
        const res = await fetch(`${apiUrl}/api/sample/${sampleId}/dissection/summary`)
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}))
          throw new Error(errData.detail || `HTTP ${res.status}`)
        }
        const data = await res.json()
        if (!cancelled) {
          // Backend (_format_behavior_item / _format_c2_item in step7) already
          // normalizes list entries to strings. Re-sanitizing here caused
          // drift (e.g. {"value":"x.com","indicator_type":"domain"} rendered
          // as just "domain"). Only guarantee that primitives are strings so
          // React can't choke on accidental objects.
          const asStringArray = (items) => (
            Array.isArray(items)
              ? items.filter(b => b != null).map(b => typeof b === 'string' ? b : (b.value || b.text || String(b)))
              : []
          )
          const sanitized = {
            ...data,
            summary: typeof data?.summary === 'string' ? data.summary : 'No summary available.',
            threat_level: typeof data?.threat_level === 'string' ? data.threat_level : 'unknown',
            risk_score: typeof data?.risk_score === 'number' ? data.risk_score : 0,
            status: data?.status,
            key_behaviors: asStringArray(data?.key_behaviors),
            suspicious_methods: Array.isArray(data?.suspicious_methods)
              ? data.suspicious_methods.filter(m => m != null)
              : [],
            c2_indicators: asStringArray(data?.c2_indicators),
            recommended_focus: Array.isArray(data?.recommended_focus)
              ? data.recommended_focus.filter(r => typeof r === 'string').map(r => r)
              : [],
          }
          setSummary(sanitized)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchSummary()
    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  if (loading) {
    return (
      <div className="tab-panel text-center p-10">
        <div className="analysis-loading-spinner" />
        <p className="mt-3 text-muted">
          Generating LLM threat assessment from dissection data...
        </p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="tab-panel text-center p-10 text-rose">
        <p>Failed to load dissection summary: {error}</p>
        <button
          className="filter-button filter-cyan mt-3"
          onClick={() => { setError(null); setLoading(true); /* re-trigger effect */ }}
        >
          Retry
        </button>
      </div>
    )
  }

  if (!summary || summary.status === 'fallback') {
    return (
        <div className="tab-panel text-center p-10 text-muted">
        <p>{summary?.summary || 'No dissection summary available.'}</p>
      </div>
    )
  }

  const threatColorClass = summary.threat_level
    ? `threat-badge-bg-${summary.threat_level}`
    : 'threat-badge-bg-unknown'

  return (
    <div className="tab-panel">
      {/* Threat Level Badge + Risk Score */}
      <div className="card flex items-center gap-3 flex-wrap">
        <div className={`threat-badge ${threatColorClass}`}>
          {summary.threat_level}
        </div>
        <div>
          <span className="text-sm text-muted">Risk Score: </span>
          <span className="heading-md">{summary.risk_score}/100</span>
        </div>
      </div>

      {/* Summary Narrative */}
      <div className="card">
        <h3 className="heading-sm">Threat Assessment</h3>
        <p className="narrative-text">
          {summary.summary}
        </p>
      </div>

      {/* Key Behaviors */}
      {summary.key_behaviors?.length > 0 && (
        <div className="card">
          <h3 className="heading-sm">
            Key Behaviors ({summary.key_behaviors.length})
          </h3>
          <ul className="detail-list">
            {summary.key_behaviors.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Suspicious Methods */}
      {summary.suspicious_methods?.length > 0 && (
        <div className="card">
          <h3 className="heading-sm">
            Suspicious Methods ({summary.suspicious_methods.length})
          </h3>
          <div className="scroll-400">
            {summary.suspicious_methods.slice(0, 15).map((m, i) => (
              <div key={i} className="code-block">
                <div className="code-block-header">
                  {typeof m === 'string'
                    ? m
                    : `${m.class || '?'}.${m.method || m.name || '?'}`}
                </div>
                {typeof m === 'object' && m && typeof m.reason === 'string' && (
                  <div className="code-block-detail">
                    {m.reason}
                  </div>
                )}
              </div>
            ))}
          </div>
          {summary.suspicious_methods.length > 15 && (
            <p className="more-link">… and {summary.suspicious_methods.length - 15} more</p>
          )}
        </div>
      )}

      {/* C2 Indicators */}
      {summary.c2_indicators?.length > 0 && (
        <div className="card">
          <h3 className="heading-sm">
            C2 Indicators ({summary.c2_indicators.length})
          </h3>
          <ul className="detail-list">
            {summary.c2_indicators.map((c, i) => (
              <li key={i} className="c2-indicator">
                {typeof c === 'string' ? c : String(c)}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommended Focus */}
      {summary.recommended_focus?.length > 0 && (
        <div className="card">
          <h3 className="heading-sm">
            Recommended Focus
          </h3>
          <ul className="detail-list">
            {summary.recommended_focus.map((r, i) => (
              <li key={i}>{typeof r === 'string' ? r : String(r)}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
})

DissectionSummaryTab.displayName = 'DissectionSummaryTab'

/**
 * Human-readable label for chain step types.
 */
const STEP_TYPE_LABELS = {
  encoded_string: 'Encoded String',
  decoding_function: 'Decoding Function',
  decoded_artifact: 'Decoded Payload',
  usage: 'Usage Site',
  c2_infrastructure: 'C2 Endpoint',
}

const STEP_TYPE_ICONS = {
  encoded_string: '🔒',
  decoding_function: '⚙️',
  decoded_artifact: '🔓',
  usage: '📍',
  c2_infrastructure: '🌐',
}

const SEVERITY_META = {
  critical: { badge: 'rose', icon: '🚨', description: 'High-confidence chain to confirmed public C2.' },
  high: { badge: 'rose', icon: '🔴', description: 'Strong indicators of malicious infrastructure.' },
  medium: { badge: 'amber', icon: '🟡', description: 'Moderate indicators — may be benign or partial chain.' },
  low: { badge: 'emerald', icon: '🟢', description: 'Weak indicators — likely benign or incomplete.' },
}

const CHAIN_THREAT_TYPE_LABELS = {
  c2_communication: 'C2 Communication',
  data_exfiltration: 'Data Exfiltration',
  payload_delivery: 'Payload Delivery',
  command_execution: 'Command Execution',
  benign: 'Benign',
  unknown: 'Unknown',
}

const CHAIN_THREAT_TYPE_COLORS = {
  c2_communication: 'rose',
  data_exfiltration: 'rose',
  payload_delivery: 'amber',
  command_execution: 'rose',
  benign: 'emerald',
  unknown: 'slate',
}

/**
 * Individual Chain Card with on-demand LLM explanation.
 */
const STEP_DESCRIPTIONS = {
  encoded_string: 'The original obfuscated or encoded string as found in the APK bytecode or resources.',
  decoding_function: 'The Java/Kotlin method or library responsible for decoding the encoded string.',
  decoded_artifact: 'The result after decoding — often a URL, domain, IP, or command payload.',
  usage: 'Where the decoded artifact is consumed — typically a network call or intent.',
  c2_infrastructure: 'The command-and-control server or endpoint contacted by the decoded payload.',
}

function tryDecode(input, method, key, customFnBody) {
  try {
    switch (method) {
      case 'base64':
        return atob(input)
      case 'hex':
        return input.replace(/\s+/g, '').replace(/([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
      case 'url':
        return decodeURIComponent(input)
      case 'xor': {
        const k = key || 'K'
        return Array.from(input, (c, i) => String.fromCharCode(c.charCodeAt(0) ^ k.charCodeAt(i % k.length))).join('')
      }
      case 'custom': {
        const fn = new Function('input', customFnBody || 'return input')
        return fn(input)
      }
      default:
        return input
    }
  } catch (e) {
    return `Error: ${e.message}`
  }
}

function ChainCard({ chain, sampleId, apiUrl }) {
  const [expanded, setExpanded] = useState(false)
  const [selectedStep, setSelectedStep] = useState(null)
  const [llmResult, setLlmResult] = useState(null)
  const [llmLoading, setLlmLoading] = useState(false)
  const [decoderInput, setDecoderInput] = useState('')
  const [decoderMethod, setDecoderMethod] = useState('base64')
  const [xorKey, setXorKey] = useState('')
  const [customFn, setCustomFn] = useState('// return decoded string\nreturn input.split("").reverse().join("")')
  const [decodedOutput, setDecodedOutput] = useState('')
  const [decodeError, setDecodeError] = useState('')
  const sevMeta = SEVERITY_META[chain.severity] || SEVERITY_META.medium

  // Fetch LLM explanation when first expanded
  useEffect(() => {
    if (!expanded || llmResult || llmLoading || !sampleId || !apiUrl) return
    setLlmLoading(true) // eslint-disable-line react-hooks/set-state-in-effect
    fetch(`${apiUrl}/api/sample/${sampleId}/explain-chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain }),
    })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.llm) setLlmResult(data.llm) })
      .catch(() => { })
      .finally(() => setLlmLoading(false))
  }, [expanded, llmResult, llmLoading, sampleId, apiUrl, chain])

  const threatType = llmResult?.threat_type
  const threatLabel = CHAIN_THREAT_TYPE_LABELS[threatType]
  const threatColor = CHAIN_THREAT_TYPE_COLORS[threatType] || 'slate'

  return (
    <div className={`card chain-card chain-severity-${chain.severity}`}>
      {/* Clickable header */}
      <div
        className="chain-header"
        onClick={() => setExpanded(v => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setExpanded(v => !v) }}
      >
        <div className="chain-header-left">
          <span className="chain-expand">{expanded ? '▾' : '▸'}</span>
          <h4>{chain.chain_id.replace('chain_', 'Chain #')}</h4>
        </div>
        <div className="chain-header-right">
          <span className="chain-step-count">{chain.steps?.length || 0} steps</span>
          <span className={`badge badge-${sevMeta.badge}`}>{sevMeta.icon} {chain.severity.toUpperCase()}</span>
          <span className="chain-confidence-badge">{Math.round(chain.confidence * 100)}%</span>
        </div>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div className="chain-body">
          <p className="chain-severity-desc">{sevMeta.description}</p>

          {/* Step flow visualization */}
          <div className="chain-steps">
            {(chain.steps || []).map((step, idx) => {
              const isSelected = selectedStep === idx
              return (
                <div key={idx} className={`chain-step ${isSelected ? 'chain-step-selected' : ''}`}>
                  <div className="chain-step-number">
                    {step.step || idx + 1}
                  </div>
                  <div
                    className="chain-step-content chain-step-clickable"
                    onClick={() => {
                      const newSelected = isSelected ? null : idx
                      setSelectedStep(newSelected)
                      if (newSelected !== null && step.type === 'decoding_function') {
                        const prevStep = chain.steps[Math.max(0, idx - 1)]
                        const enc = prevStep?.artifact || prevStep?.original_string || step.original_string || step.artifact || ''
                        setDecoderInput(enc)
                        setDecodedOutput('')
                        setDecodeError('')
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') {
                      const newSelected = isSelected ? null : idx
                      setSelectedStep(newSelected)
                      if (newSelected !== null && step.type === 'decoding_function') {
                        const prevStep = chain.steps[Math.max(0, idx - 1)]
                        const enc = prevStep?.artifact || prevStep?.original_string || step.original_string || step.artifact || ''
                        setDecoderInput(enc)
                        setDecodedOutput('')
                        setDecodeError('')
                      }
                    } }}
                  >
                    <div className="chain-step-header">
                      <span className="chain-step-icon">{STEP_TYPE_ICONS[step.type] || '❓'}</span>
                      <span className="chain-step-type">
                        {STEP_TYPE_LABELS[step.type] || step.type}
                      </span>
                      <span className="chain-step-expand-hint">{isSelected ? '▾' : '▸'}</span>
                    </div>
                    <div className="chain-step-artifact">
                      {step.original_string && step.original_string !== step.artifact ? (
                        <span className="chain-step-artifact-pair">
                          <span className="chain-step-original" title="Original encoded string">{step.original_string}</span>
                          <span className="chain-step-arrow">→</span>
                          <span className="chain-step-decoded">{step.artifact || '—'}</span>
                        </span>
                      ) : (
                        step.artifact || '—'
                      )}
                    </div>

                    {/* Detail panel — shown when step is selected */}
                    {isSelected && (
                      <div className="chain-step-detail">
                        <p className="chain-step-description">
                          {STEP_DESCRIPTIONS[step.type] || 'Step in the threat chain.'}
                        </p>

                        <div className="chain-step-detail-grid">
                          {step.original_string && step.original_string !== step.artifact ? (
                            <>
                              <div className="chain-step-detail-row">
                                <span className="detail-label">Original String</span>
                                <span className="detail-value detail-artifact">
                                  {step.original_string}
                                </span>
                              </div>
                              <div className="chain-step-detail-row">
                                <span className="detail-label">Decoded Content</span>
                                <span className="detail-value detail-artifact">
                                  {step.artifact || '—'}
                                </span>
                              </div>
                            </>
                          ) : (
                            <div className="chain-step-detail-row">
                              <span className="detail-label">Artifact Content</span>
                              <span className="detail-value detail-artifact">
                                {step.artifact || '—'}
                              </span>
                            </div>
                          )}
                          {step.source_location && (
                            <div className="chain-step-detail-row">
                              <span className="detail-label">Source</span>
                              <span className="detail-value detail-source">
                                {step.source_location}
                              </span>
                            </div>
                          )}
                          {step.confidence !== undefined && (
                            <div className="chain-step-detail-row">
                              <span className="detail-label">Confidence</span>
                              <span className="detail-value">
                                <span className="confidence-bar-wrapper">
                                  <span
                                    className="confidence-bar-fill"
                                    style={{ width: `${Math.round(step.confidence * 100)}%` }}
                                  />
                                </span>
                                {Math.round(step.confidence * 100)}%
                              </span>
                            </div>
                          )}
                        </div>

                        {step.type === 'decoding_function' && (
                          <div className="chain-step-decoder">
                            <h5 className="decoder-title">⚙️ Interactive Decoder</h5>
                            <div className="decoder-input-row">
                              <label className="detail-label">Encoded Input</label>
                              <textarea
                                className="decoder-textarea"
                                rows={2}
                                value={decoderInput}
                                onChange={(e) => setDecoderInput(e.target.value)}
                                placeholder="Paste or edit the encoded string..."
                              />
                            </div>
                            <div className="decoder-controls">
                              <div className="decoder-method-group">
                                <label className="detail-label">Method</label>
                                <select
                                  className="decoder-select"
                                  value={decoderMethod}
                                  onChange={(e) => setDecoderMethod(e.target.value)}
                                >
                                  <option value="base64">Base64</option>
                                  <option value="hex">Hex</option>
                                  <option value="url">URL Decode</option>
                                  <option value="xor">XOR</option>
                                  <option value="custom">Custom JS</option>
                                </select>
                              </div>
                              {decoderMethod === 'xor' && (
                                <div className="decoder-key-group">
                                  <label className="detail-label">XOR Key</label>
                                  <input
                                    className="decoder-input"
                                    type="text"
                                    value={xorKey}
                                    onChange={(e) => setXorKey(e.target.value)}
                                    placeholder="Key"
                                  />
                                </div>
                              )}
                              <div className="decoder-decode-group">
                                <button
                                  className="decoder-decode-btn"
                                  onClick={() => {
                                    setDecodeError('')
                                    setDecodedOutput(tryDecode(decoderInput, decoderMethod, xorKey, customFn))
                                  }}
                                >
                                  Decode
                                </button>
                              </div>
                            </div>
                            {decoderMethod === 'custom' && (
                              <div className="decoder-custom-group">
                                <label className="detail-label">Custom Decode Function</label>
                                <textarea
                                  className="decoder-textarea decoder-textarea-code"
                                  rows={4}
                                  value={customFn}
                                  onChange={(e) => setCustomFn(e.target.value)}
                                  placeholder="Write a JavaScript function body. Use 'input' variable."
                                />
                              </div>
                            )}
                            <div className="decoder-output-row">
                              <label className="detail-label">Decoded Output</label>
                              <div className="decoder-output">{decodedOutput || 'Click Decode to see the result.'}</div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {!isSelected && step.source_location && (
                      <div className="chain-step-source">
                        📄 {step.source_location}
                      </div>
                    )}
                    {!isSelected && step.confidence !== undefined && (
                      <div className="chain-step-confidence">
                        Confidence: {Math.round(step.confidence * 100)}%
                      </div>
                    )}
                  </div>
                  {idx < (chain.steps?.length || 0) - 1 && (
                    <div className="chain-step-connector" />
                  )}
                </div>
              )
            })}
          </div>

          {/* LLM explanation section */}
          <div className="chain-llm-section">
            {llmLoading ? (
              <div className="llm-shimmer">
                <div className="shimmer-bar shimmer-bar-long" />
                <div className="shimmer-bar shimmer-bar-medium" />
              </div>
            ) : llmResult ? (
              <div className="llm-result">
                <div className="llm-result-header">
                  <span className="llm-icon">🧠</span>
                  <span className="llm-label">AI Analysis</span>
                  {threatLabel && (
                    <span className={`badge badge-${threatColor} badge-xs`}>
                      {threatLabel}
                    </span>
                  )}
                  {llmResult.confidence != null && (
                    <span className="llm-confidence">
                      {Math.round(llmResult.confidence * 100)}% confidence
                    </span>
                  )}
                </div>
                <p className="llm-summary-text">{llmResult.summary}</p>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Severity ordering for sort-by-severity.
 */
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const SORT_OPTIONS = [
  { id: 'severity', label: 'Severity' },
  { id: 'confidence', label: 'Confidence' },
  { id: 'steps', label: 'Step Count' },
]

/**
 * Threat Chains Tab
 */
const ChainsTab = memo(({ result, apiUrl, sampleId }) => {
  const chains = useMemo(() => result?.threat_chains || [], [result?.threat_chains])
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [sortBy, setSortBy] = useState('severity')

  // Summary stats
  const severityCounts = chains.reduce((acc, c) => {
    acc[c.severity] = (acc[c.severity] || 0) + 1
    return acc
  }, {})
  const avgConfidence = chains.length > 0
    ? Math.round((chains.reduce((s, c) => s + c.confidence, 0) / chains.length) * 100)
    : 0

  // Filtered + sorted chains
  const visibleChains = useMemo(() => {
    let list = chains
    if (filterSeverity !== 'all') {
      list = list.filter(c => c.severity === filterSeverity)
    }
    list = [...list].sort((a, b) => {
      if (sortBy === 'severity') {
        return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
      }
      if (sortBy === 'confidence') {
        return b.confidence - a.confidence
      }
      // sortBy === 'steps'
      return (b.steps?.length || 0) - (a.steps?.length || 0)
    })
    return list
  }, [chains, filterSeverity, sortBy])

  if (chains.length === 0) {
    return (
      <div className="tab-panel">
        <div className="card chains-explainer">
          <h3>⛓️ What Are Threat Chains?</h3>
          <p>
            Threat chains are <strong>directed evidence links</strong> that trace how an obfuscated string
            flows through the APK — from its encoded form, through decoding logic, to the final
            command-and-control (C2) endpoint it reveals.
          </p>
          <p>
            Each chain represents a single "attack path": an encoded string is identified in Step 3,
            decoded in Step 4, and correlated with C2 infrastructure in Step 5. Chains with higher
            confidence scores indicate that multiple independent indicators agree on the same malicious
            behavior.
          </p>
          <p className="chains-explainer-note">
            No threat chains were detected in this sample. This may mean the APK does not use
            obfuscated C2 communication, or the decoded payloads did not match known infrastructure.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel">
      {/* Explanation card */}
      <div className="card chains-explainer">
        <h3>⛓️ What Are Threat Chains?</h3>
        <p>
          Threat chains are <strong>directed evidence links</strong> that trace how an obfuscated string
          flows through the APK — from its encoded form, through decoding logic, to the final
          command-and-control (C2) endpoint it reveals.
        </p>
        <p>
          Each chain has up to 5 steps: <strong>Encoded String</strong> → <strong>Decoding Function</strong> →
          <strong>Decoded Payload</strong> → <strong>Usage Site</strong> → <strong>C2 Endpoint</strong>. Chains
          with higher confidence scores indicate that multiple independent indicators agree on the same
          malicious behavior.
        </p>
      </div>

      {/* Summary stats */}
      <div className="chains-summary">
        <div className="chains-summary-stat">
          <span className="chains-summary-value">{chains.length}</span>
          <span className="chains-summary-label">Total Chains</span>
        </div>
        <div className="chains-summary-stat">
          <span className="chains-summary-value">{avgConfidence}%</span>
          <span className="chains-summary-label">Avg Confidence</span>
        </div>
        {severityCounts.critical > 0 && (
          <div className="chains-summary-stat chains-summary-critical">
            <span className="chains-summary-value">{severityCounts.critical}</span>
            <span className="chains-summary-label">Critical</span>
          </div>
        )}
        {severityCounts.high > 0 && (
          <div className="chains-summary-stat chains-summary-high">
            <span className="chains-summary-value">{severityCounts.high}</span>
            <span className="chains-summary-label">High</span>
          </div>
        )}
        {severityCounts.medium > 0 && (
          <div className="chains-summary-stat chains-summary-medium">
            <span className="chains-summary-value">{severityCounts.medium}</span>
            <span className="chains-summary-label">Medium</span>
          </div>
        )}
        {severityCounts.low > 0 && (
          <div className="chains-summary-stat chains-summary-low">
            <span className="chains-summary-value">{severityCounts.low}</span>
            <span className="chains-summary-label">Low</span>
          </div>
        )}
      </div>

      {/* Filter / Sort toolbar */}
      <div className="chains-toolbar">
        <div className="chains-toolbar-filters">
          <span className="chains-toolbar-label">Filter</span>
          <button
            className={`chains-filter-btn ${filterSeverity === 'all' ? 'active' : ''}`}
            onClick={() => setFilterSeverity('all')}
          >
            All ({chains.length})
          </button>
          {['critical', 'high', 'medium', 'low'].filter(sev => severityCounts[sev] > 0).map(sev => (
            <button
              key={sev}
              className={`chains-filter-btn chains-filter-${sev} ${filterSeverity === sev ? 'active' : ''}`}
              onClick={() => setFilterSeverity(filterSeverity === sev ? 'all' : sev)}
            >
              {SEVERITY_META[sev]?.icon || '❓'} {sev.charAt(0).toUpperCase() + sev.slice(1)} ({severityCounts[sev]})
            </button>
          ))}
        </div>
        <div className="chains-toolbar-sort">
          <span className="chains-toolbar-label">Sort</span>
          <select
            className="chains-sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            {SORT_OPTIONS.map(opt => (
              <option key={opt.id} value={opt.id}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Results count when filtered */}
      {filterSeverity !== 'all' && (
        <p className="chains-filter-count">
          Showing {visibleChains.length} of {chains.length} chains
        </p>
      )}

      {/* Chain list */}
      <div className="chains-list">
        {visibleChains.length === 0 ? (
          <p className="chains-empty-filter">No chains match the current filter.</p>
        ) : (
          visibleChains.map(chain => (
            <ChainCard
              key={chain.chain_id}
              chain={chain}
              sampleId={sampleId}
              apiUrl={apiUrl}
            />
          ))
        )}
      </div>
    </div>
  )
})

ChainsTab.displayName = 'ChainsTab'

const MAX_RETRIES = 3
const RETRY_BASE_MS = 2000

const ERROR_MESSAGES = {
  timeout: 'Analysis timed out. The APK may be very large or complex.',
  malformed: 'The APK file appears to be corrupted or invalid.',
  disk_space: 'Server ran out of disk space. Contact administrators.',
  not_found: 'APK file not found on the server.',
  network: 'Network error. Check your connection and try again.',
  internal_error: 'An unexpected server error occurred.',
  pipeline_error: 'Analysis pipeline failed. Contact administrators.',
}

function useRetryState() {
  const [retryCount, setRetryCount] = useState(0)
  const [isRetrying, setIsRetrying] = useState(false)
  const [countdown, setCountdown] = useState(0)

  const scheduleRetry = useCallback((onRetry) => {
    if (retryCount >= MAX_RETRIES) return
    setIsRetrying(true)

    const delay = RETRY_BASE_MS * Math.pow(2, retryCount)
    const seconds = Math.ceil(delay / 1000)
    setCountdown(seconds)

    const interval = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval)
          return 0
        }
        return prev - 1
      })
    }, 1000)

    setTimeout(() => {
      clearInterval(interval)
      setIsRetrying(false)
      setCountdown(0)
      setRetryCount((c) => c + 1)
      if (onRetry) onRetry()
    }, delay)
  }, [retryCount])

  const reset = useCallback(() => {
    setRetryCount(0)
    setIsRetrying(false)
    setCountdown(0)
  }, [])

  return { retryCount, isRetrying, countdown, scheduleRetry, reset }
}

function ErrorState({ analysisState, onRetry }) {
  const { retryCount, isRetrying, countdown, scheduleRetry } = useRetryState()

  const errorType = analysisState.errorType || 'internal_error'
  const errorMessage = analysisState.error || ERROR_MESSAGES[errorType] || 'Unknown error'
  const isRetryable = retryCount < MAX_RETRIES && errorType !== 'malformed' && errorType !== 'disk_space'

  const handleRetry = () => {
    scheduleRetry(() => {
      if (onRetry) onRetry()
    })
  }

  return (
    <div className="analysis-error">
      <h2>Analysis Failed</h2>
      <p>{errorMessage}</p>

      {isRetrying && (
        <div className="retry-loading">
          <div className="retry-spinner" />
          <p className="retry-countdown">Retrying in {countdown}s... (Attempt {retryCount + 1}/{MAX_RETRIES})</p>
        </div>
      )}

      {!isRetrying && isRetryable && (
        <div className="retry-actions">
          <p className="retry-attempt-info">Attempt {retryCount + 1} of {MAX_RETRIES}</p>
          <button className="retry-button" onClick={handleRetry}>
            Retry Analysis
          </button>
        </div>
      )}

      {!isRetryable && !isRetrying && (
        <div className="retry-exhausted">
          <p>Maximum retries reached. Please contact support.</p>
          <a className="retry-support-link" href="mailto:support@droidforenix.local">
            Contact Support
          </a>
        </div>
      )}
    </div>
  )
}

/**
 * Main AnalysisView Component
 */
function AnalysisView({ sample, analysisState, apiUrl, onRetry }) {
  const isAnalyzing = analysisState.status === 'running'
  const isComplete = analysisState.status === 'complete'
  const hasError = analysisState.status === 'error'

  if (hasError) {
    return <ErrorState analysisState={analysisState} onRetry={onRetry} />
  }

  if (isAnalyzing) {
    return <LoadingState analysisState={analysisState} />
  }

  if (isComplete) {
    return <ResultView analysisState={analysisState} apiUrl={apiUrl} sample={sample} />
  }

  return (
    <div className="analysis-idle">
      <p>Upload an APK to begin analysis.</p>
    </div>
  )
}

const SEVERITY_CONFIG = {
  critical: { color: 'var(--accent-rose)', badge: 'rose', order: 0 },
  high: { color: 'var(--accent-rose)', badge: 'rose', order: 1 },
  medium: { color: 'var(--accent-amber)', badge: 'amber', order: 2 },
  low: { color: 'var(--accent-emerald)', badge: 'emerald', order: 3 },
}

function SevBadge({ severity }) {
  const cls = severity ? `sev-badge sev-badge-${severity}` : 'sev-badge sev-badge-slate'
  return <span className={cls}>{severity}</span>
}

const SecretsTab = memo(({ result }) => {
  const secrets = result?.hardcoded_secrets || []
  const risk = result?.secret_risk || {}
  const bySev = risk?.by_severity || {}
  const total = (bySev.critical || 0) + (bySev.high || 0) + (bySev.medium || 0) + (bySev.low || 0)

  if (!secrets.length) {
    return (
      <div className="tab-panel">
        <div className="card card-empty">
          <p className="text-muted">No hardcoded secrets detected.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="tab-panel">
      <div className="secrets-header">
        <div>
          <small className="secrets-label">EXPOSED SECRET POSTURE</small>
          <strong className="secrets-header-total">{total} findings</strong>
        </div>
        <div className="secrets-header-right">
          {['critical', 'high', 'medium'].map(s => (
            <div key={s} className="secrets-metric">
              <div className="secrets-metric-value" style={{ color: SEVERITY_CONFIG[s].color }}>{bySev[s] || 0}</div>
              <small className="secrets-btn">{s}</small>
            </div>
          ))}
        </div>
        <div className="text-right">
          <small className="secrets-label">SECRETS RISK</small>
          <strong className="secrets-risk-value" style={{ color: risk.risk_score > 60 ? 'var(--accent-rose)' : 'var(--accent-amber)' }}>{risk.risk_score || 0}</strong>
        </div>
      </div>

      <div className="secrets-bar-chart">
        {['critical', 'high', 'medium', 'low'].map(s => {
          const cfg = SEVERITY_CONFIG[s]
          const count = bySev[s] || 0
          return count > 0 ? (
            <div key={s} className="secrets-bar" style={{ flex: count, background: cfg.color }} />
          ) : null
        })}
      </div>

      <div className="secrets-grid">
        {secrets.sort((a, b) => (SEVERITY_CONFIG[a.severity]?.order ?? 9) - (SEVERITY_CONFIG[b.severity]?.order ?? 9)).map((s, i) => {
          const cfg = SEVERITY_CONFIG[s.severity] || { color: 'var(--text-muted)' }
          const loc = s.source || s.source_file || '?'
          return (
            <article key={i} className="secret-item" style={{ borderTopColor: cfg.color }}>
              <div className="secret-item-header">
                <SevBadge severity={s.severity} />
                <strong className="secret-item-type">{s.secret_type}</strong>
              </div>
              <p className="secret-item-value">{s.value}</p>
              {s.decoded && (
                <p className="secret-item-decoded">✓ {s.decoded}</p>
              )}
              <div className="secret-item-location">
                {loc}{s.occurrence_count > 1 ? ` · ${s.occurrence_count} occurrences` : ''}
              </div>
            </article>
          )
        })}
      </div>
    </div>
  )
})

SecretsTab.displayName = 'SecretsTab'

export default memo(AnalysisView)
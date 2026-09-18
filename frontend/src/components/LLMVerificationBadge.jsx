import { memo } from 'react'
import './LLMVerificationBadge.css'

const VERDICT_CONFIG = {
  true: { text: 'MALICIOUS', color: '#FF3333', icon: '🔴' },
  false: { text: 'BENIGN', color: '#33AA33', icon: '🟢' },
  null: { text: 'UNKNOWN', color: '#FFAA00', icon: '🟡' },
  undefined: { text: 'NO VERDICT', color: '#999999', icon: '⚪' }
}

const CONFIDENCE_CONFIG = {
  high: { icon: '●●●', color: '#FF0000' },
  medium: { icon: '●●○', color: '#FFAA00' },
  low: { icon: '●○○', color: '#FFFF00' },
  unknown: { icon: '○○○', color: '#999999' }
}

const FP_RISK_CONFIG = {
  low: { color: '#33AA33' },
  medium: { color: '#FFAA00' },
  high: { color: '#FF3333' },
  unknown: { color: '#999999' }
}

function LLMVerificationBadge({ llmResult, verbose = false }) {
  if (!llmResult) return null

  if (llmResult.status === 'disabled' || llmResult.status === 'ollama_disabled') {
    return (
      <div className="llm-badge llm-badge-disabled">
        <span className="llm-badge-warning-icon">⚠️</span>
        <span>LLM Verification Disabled (Ollama not available)</span>
      </div>
    )
  }

  if (llmResult.status === 'error') {
    return (
      <div className="llm-badge llm-badge-error">
        <span className="llm-badge-warning-icon">⚠️</span>
        <span>LLM Verification Failed: {llmResult.error}</span>
      </div>
    )
  }

  const verdict = llmResult.is_malicious
  const verdictCfg = VERDICT_CONFIG[String(verdict)]
  const confidence = llmResult.confidence || 'unknown'
  const confCfg = CONFIDENCE_CONFIG[confidence] || CONFIDENCE_CONFIG.unknown
  const fpRisk = llmResult.false_positive_likelihood || 'unknown'
  const fpCfg = FP_RISK_CONFIG[fpRisk] || FP_RISK_CONFIG.unknown
  const reasoning = llmResult.reasoning || ''
  const latency = llmResult.latency_seconds || 0
  const isSuccess = llmResult.status === 'success'

  return (
    <div className="llm-badge">
      <div className="llm-badge-row">
        <span
          className="llm-verdict-badge"
          style={{ color: verdictCfg.color, borderColor: verdictCfg.color }}
        >
          {verdictCfg.icon} {verdictCfg.text}
        </span>

        <span className="llm-confidence-section">
          <span className="llm-label">Confidence:</span>
          <span className="llm-confidence-icons" style={{ color: confCfg.color }}>
            {confCfg.icon}
          </span>
          <span className="llm-confidence-value">{confidence}</span>
        </span>

        <span className="llm-fp-risk-section">
          <span className="llm-label">FP Risk:</span>
          <span className="llm-fp-risk-value" style={{ color: fpCfg.color }}>
            {fpRisk}
          </span>
        </span>

        {isSuccess && latency > 0 && (
          <span className="llm-latency">{latency.toFixed(1)}s</span>
        )}
      </div>

      {reasoning && (
        <div className="llm-reasoning-box">
          <span className="llm-reasoning-label">Reasoning:</span>
          <p className="llm-reasoning-text">"{reasoning}"</p>
        </div>
      )}

      {verbose && (
        <details className="llm-verbose-details">
          <summary className="llm-verbose-summary">Show Details</summary>
          <pre className="llm-verbose-content">
            {JSON.stringify(llmResult, null, 2)}
          </pre>
        </details>
      )}
    </div>
  )
}

export default memo(LLMVerificationBadge)

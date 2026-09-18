import { useState, memo } from 'react'
import LLMVerificationBadge from './LLMVerificationBadge'
import MITREDisplay from './MITREDisplay'
import './ThreatConsolidationSummary.css'

const CLASSIFICATION_CONFIG = {
  malware: { color: '#FF0000', bgColor: '#FFE6E6', icon: '🔴' },
  suspicious: { color: '#FFAA00', bgColor: '#FFF3E6', icon: '🟡' },
  benign: { color: '#00AA00', bgColor: '#E6F7E6', icon: '🟢' },
  unknown: { color: '#999999', bgColor: '#F5F5F5', icon: '⚪' }
}

const STAGE_CONFIG = [
  { key: 'stage_0_metadata', stage: 'Metadata', icon: '📋' },
  { key: 'stage_1_threat_indicators', stage: 'Threat Indicators', icon: '⚠️' },
  { key: 'stage_2_jadx_analysis', stage: 'Code Review', icon: '🔍' },
  { key: 'stage_3_dns_enrichment', stage: 'DNS Enrichment', icon: '🌐' },
  { key: 'stage_4_cross_validation', stage: 'Cross-Validation', icon: '✓' }
]

const VERDICT_COLORS = {
  true: '#FF0000',
  false: '#00AA00',
  null: '#FFAA00',
  undefined: '#999999'
}

const VERDICT_TEXT = {
  true: 'MALICIOUS',
  false: 'BENIGN',
  null: 'UNKNOWN',
  undefined: 'NO VERDICT'
}

const CONFIDENCE_ICONS = {
  high: '●●●',
  medium: '●●○',
  low: '●○○',
  unknown: '○○○'
}

function ThreatConsolidationSummary({ report, onDownloadReport }) {
  const [expandedSections, setExpandedSections] = useState({
    stages: true,
    synthesis: true,
    actions: true,
    iocs: false
  })

  if (!report) return <div className="tcs-no-report">No report available</div>

  const threat = report.llm_assessment || report.threat_assessment || {}
  const synthesis = threat.llm_synthesis || threat || {}
  const rawSeverity = threat.severity || 'unknown'
  const classification = report.final_classification || threat.classification || 
    (rawSeverity === 'critical' || rawSeverity === 'high' ? 'malware' : rawSeverity === 'medium' ? 'suspicious' : rawSeverity === 'low' ? 'benign' : 'unknown')

  // Convert confidence to a display status: high/medium/low
  let confidence = 'low'
  const numericConfidence = typeof threat.confidence === 'number' ? threat.confidence : parseFloat(threat.confidence)
  if (!isNaN(numericConfidence)) {
    if (numericConfidence >= 0.8) confidence = 'high'
    else if (numericConfidence >= 0.5) confidence = 'medium'
    else confidence = 'low'
  } else if (typeof threat.confidence === 'string') {
    confidence = threat.confidence.toLowerCase()
  }

  const riskScore = threat.risk_score || 0

  const classCfg = CLASSIFICATION_CONFIG[classification] || CLASSIFICATION_CONFIG.unknown

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }))
  }

  const stageVerdicts = STAGE_CONFIG.map(({ key, stage, icon }) => {
    const stageData = report[key] || {}
    const llmResult = stageData.llm_verification
    return { stage, icon, result: llmResult }
  }).filter(v => v.result)

  const maliciousCount = stageVerdicts.filter(v => v.result?.is_malicious === true).length
  const benignCount = stageVerdicts.filter(v => v.result?.is_malicious === false).length
  const unknownCount = stageVerdicts.filter(v => v.result?.is_malicious === null).length

  // Build network indicators dynamically if not present
  const c2s = report.c2_infrastructure || []
  const uniqueIps = Array.from(new Set(c2s.map(c => c.ip).filter(Boolean)))
  const network_indicators = report.network_indicators || (uniqueIps.length > 0 ? {
    total_unique_ips: uniqueIps.length,
    ips: uniqueIps.map(ip => {
      const c2Match = c2s.find(c => c.ip === ip) || {}
      return {
        ip,
        threat_level: c2Match.classification || 'unknown',
        circl_pdns: { record_count: c2Match.circl?.pdns_domain?.count || 0 },
        live_dns: { responsive: c2Match.live_dns?.resolves || false }
      }
    })
  } : null)

  const recommendedActions = synthesis.recommended_actions || threat.recommended_actions || []

  return (
    <div className="tcs-container">
      <div
        className="tcs-classification-card"
        style={{ borderColor: classCfg.color, backgroundColor: classCfg.bgColor }}
      >
        <div className="tcs-classification-header">
          <h2 style={{ color: classCfg.color }}>
            {classCfg.icon} {classification.toUpperCase()}
          </h2>
        </div>

        <div className="tcs-classification-metrics">
          <div className="tcs-metric">
            <span className="tcs-metric-label">Confidence:</span>
            <span className="tcs-metric-value">
              {CONFIDENCE_ICONS[confidence] || CONFIDENCE_ICONS.unknown} {confidence.toUpperCase()}
            </span>
          </div>

          <div className="tcs-metric">
            <span className="tcs-metric-label">Risk Score:</span>
            <span className="tcs-metric-value">{riskScore}/100</span>
          </div>

          <div className="tcs-metric">
            <span className="tcs-metric-label">Stage Consensus:</span>
            <span className="tcs-metric-value">
              <span style={{ color: '#FF0000' }}>{maliciousCount} Malicious</span>
              {' | '}
              <span style={{ color: '#00AA00' }}>{benignCount} Benign</span>
              {' | '}
              <span style={{ color: '#999' }}>{unknownCount} Unknown</span>
            </span>
          </div>
        </div>
      </div>

      {stageVerdicts.length > 0 && (
        <div className="tcs-section">
          <div className="tcs-section-header" onClick={() => toggleSection('stages')}>
            <span className="tcs-section-title">
              {expandedSections.stages ? '▼' : '▶'} Stage Verdicts
            </span>
          </div>

          {expandedSections.stages && (
            <div className="tcs-section-content">
              <div className="tcs-stage-grid">
                {stageVerdicts.map(({ stage, icon, result }) => {
                  const verdict = result?.is_malicious
                  const verdictColor = VERDICT_COLORS[String(verdict)]
                  const verdictText = VERDICT_TEXT[String(verdict)]

                  return (
                    <div
                      key={stage}
                      className="tcs-stage-card"
                      style={{ borderLeftColor: verdictColor }}
                    >
                      <div className="tcs-stage-card-header">
                        <span className="tcs-stage-icon">{icon}</span>
                        <span className="tcs-stage-name">{stage}</span>
                      </div>

                      <div className="tcs-stage-verdict" style={{ color: verdictColor }}>
                        {verdictText}
                      </div>

                      {result?.confidence && (
                        <div className="tcs-stage-confidence">
                          {result.confidence.toUpperCase()}
                        </div>
                      )}

                      <LLMVerificationBadge
                        llmResult={result}
                        stage={stage.toLowerCase().replace(/\s+/g, '_')}
                        verbose={false}
                      />
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="tcs-section">
        <div className="tcs-section-header" onClick={() => toggleSection('synthesis')}>
          <span className="tcs-section-title">
            {expandedSections.synthesis ? '▼' : '▶'} LLM Synthesis
          </span>
        </div>

        {expandedSections.synthesis && (
          <div className="tcs-section-content">
            {(synthesis.reasoning || synthesis.narrative) && (
              <div className="tcs-synthesis-box">
                <p className="tcs-synthesis-text">"{synthesis.reasoning || synthesis.narrative}"</p>
              </div>
            )}

            {synthesis.mitre_tactics && synthesis.mitre_tactics.length > 0 && (
              <div style={{ marginTop: '12px' }}>
                <MITREDisplay tactics={synthesis.mitre_tactics} />
              </div>
            )}

            {synthesis.behavioral_analysis && (
              <div className="tcs-synthesis-box">
                <span className="tcs-synthesis-label">Behavioral Analysis:</span>
                <p className="tcs-synthesis-text">{synthesis.behavioral_analysis}</p>
              </div>
            )}

            {synthesis.ioc_assessment && (
              <div className="tcs-synthesis-box">
                <span className="tcs-synthesis-label">IOC Assessment:</span>
                <p className="tcs-synthesis-text">{synthesis.ioc_assessment}</p>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="tcs-section">
        <div className="tcs-section-header" onClick={() => toggleSection('actions')}>
          <span className="tcs-section-title">
            {expandedSections.actions ? '▼' : '▶'} Recommended Actions
          </span>
        </div>

        {expandedSections.actions && (
          <div className="tcs-section-content">
            {recommendedActions.length > 0 ? (
              <ol className="tcs-actions-list">
                {recommendedActions.map((action, idx) => (
                  <li key={idx} className="tcs-action-item">{action}</li>
                ))}
              </ol>
            ) : (
              <p className="tcs-no-data">No specific actions recommended</p>
            )}
          </div>
        )}
      </div>

      {network_indicators && network_indicators.total_unique_ips > 0 && (
        <div className="tcs-section">
          <div className="tcs-section-header" onClick={() => toggleSection('iocs')}>
            <span className="tcs-section-title">
              {expandedSections.iocs ? '▼' : '▶'} Network Indicators (IOCs)
            </span>
          </div>

          {expandedSections.iocs && (
            <div className="tcs-section-content">
              <div className="tcs-ioc-summary">
                <span>Total IPs: {network_indicators.total_unique_ips}</span>
              </div>

              <div className="tcs-ioc-list">
                {network_indicators.ips &&
                  network_indicators.ips.slice(0, 5).map((ip) => (
                    <div key={ip.ip} className="tcs-ioc-card">
                      <div className="tcs-ioc-ip">{ip.ip}</div>
                      <div className="tcs-ioc-meta">
                        <span className="tcs-ioc-meta-item">
                          Threat: <strong>{ip.threat_level}</strong>
                        </span>
                        <span className="tcs-ioc-meta-item">
                          CIRCL Records: <strong>{ip.circl_pdns?.record_count || 0}</strong>
                        </span>
                        <span className="tcs-ioc-meta-item">
                          Responsive: <strong>{ip.live_dns?.responsive ? 'Yes' : 'No'}</strong>
                        </span>
                      </div>
                    </div>
                  ))}
              </div>

              {network_indicators.total_unique_ips > 5 && (
                <p className="tcs-more-iocs">
                  ... and {network_indicators.total_unique_ips - 5} more
                </p>
              )}
            </div>
          )}
        </div>
      )}

      <div className="tcs-export-section">
        {onDownloadReport && (
          <button className="tcs-download-button" onClick={onDownloadReport}>
            📥 Download PDF Report
          </button>
        )}

        <div className="tcs-report-meta">
          <span>Case ID: {report.case_id || report.sample_id || 'N/A'}</span>
          <span>Analysis: {report.analysis_timestamp || report.timestamp || 'N/A'}</span>
        </div>
      </div>
    </div>
  )
}

export default memo(ThreatConsolidationSummary)

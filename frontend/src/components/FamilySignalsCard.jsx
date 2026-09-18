import { useState, useEffect } from 'react'
import { fetchWithCache } from '../utils/fetchWithCache'
import ConfidenceBar from './ConfidenceBar'

const METHOD_META = {
  ground_truth: { label: 'Ground Truth', color: 'var(--accent-emerald)' },
  yara: { label: 'YARA', color: 'var(--accent-cyan)' },
  signature: { label: 'Signature', color: 'var(--accent-amber)' },
  llm: { label: 'LLM', color: 'var(--accent-violet)' },
  none: { label: 'Unverified', color: 'var(--text-muted)' },
  error: { label: 'Error', color: 'var(--accent-rose)' },
}

const SIGNAL_LABELS = {
  permissions_match: 'Permissions Match',
  c2_overlap: 'C2 Overlap',
  obfuscation_pattern: 'Obfuscation Pattern',
  code_similarity: 'Code Similarity',
}

export default function FamilySignalsCard({ sampleId, apiUrl }) {
  const [expanded, setExpanded] = useState(false)
  const [attribution, setAttribution] = useState(null)
  const [threatIntel, setThreatIntel] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!sampleId || !apiUrl) return
    let cancelled = false

    setLoading(true)
    Promise.all([
      fetchWithCache(`${apiUrl}/api/sample/${sampleId}/attribution`).catch(() => null),
      fetchWithCache(`${apiUrl}/api/sample/${sampleId}/threat-intel`).catch(() => null),
    ]).then(([attrData, intelData]) => {
      if (cancelled) return
      setAttribution(attrData)
      setThreatIntel(intelData)
      setLoading(false)
    })

    return () => { cancelled = true }
  }, [sampleId, apiUrl])

  const familyObj = threatIntel?.family || null
  const primaryFamily = familyObj?.family || attribution?.family || null
  const primaryConfidence = familyObj?.confidence ?? attribution?.confidence ?? null
  const primaryMethod = familyObj?.method || null
  const candidates = (familyObj?.candidates || []).filter(c => c.family && primaryFamily && c.family.toLowerCase() !== primaryFamily.toLowerCase())
  const breakdown = attribution?.confidence_breakdown || null
  const relatedCount = attribution?.related_samples?.length || null

  const isUnknown = !primaryFamily || primaryFamily.toLowerCase() === 'unknown' || (primaryConfidence != null && primaryConfidence === 0)
  const hasData = (!isUnknown && primaryFamily) || candidates.length > 0 || breakdown || relatedCount

  if (loading) return null
  if (!hasData) return null

  const methodMeta = METHOD_META[primaryMethod] || METHOD_META.none

  return (
    <div className="card family-signals-card">
      <div
        className="family-signals-header"
        onClick={() => setExpanded(v => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setExpanded(v => !v) }}
      >
        <h4>Family Signals</h4>
        <span className="family-signals-toggle">{expanded ? '▾' : '▸'}</span>
      </div>

      {!expanded && (
        <div className="family-signals-preview">
          {primaryFamily ? (
            <span>
              {primaryFamily}
              {primaryConfidence != null && (
                <span className="family-signals-preview-conf">
                  {' '}({Math.round(primaryConfidence * 100)}%)
                </span>
              )}
            </span>
          ) : (
            <span className="family-signals-none">No primary match</span>
          )}
        </div>
      )}

      {expanded && (
        <div className="family-signals-body">
          {!isUnknown && primaryFamily && (
            <div className="family-signals-primary">
              <div className="family-signals-primary-head">
                <span className="family-signals-primary-name">{primaryFamily}</span>
                {primaryConfidence != null && (
                  <span className="family-signals-primary-conf">
                    {Math.round(primaryConfidence * 100)}%
                  </span>
                )}
                {primaryMethod && (
                  <span
                    className="family-signals-method-badge"
                    style={{
                      background: `${methodMeta.color}22`,
                      color: methodMeta.color,
                      borderColor: methodMeta.color,
                    }}
                  >
                    {methodMeta.label}
                  </span>
                )}
              </div>

              {familyObj?.reasoning && (
                <p className="family-signals-reasoning">{familyObj.reasoning}</p>
              )}

              {breakdown && (
                <div className="family-signals-breakdown">
                  <p className="family-signals-breakdown-label">Signal Confidence</p>
                  {Object.entries(SIGNAL_LABELS).map(([key, label]) => {
                    const val = breakdown[key]
                    if (val == null) return null
                    return (
                      <ConfidenceBar
                        key={key}
                        value={val}
                        label={label}
                        size="sm"
                      />
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {candidates.length > 0 && (
            <div className="family-signals-candidates">
              <p className="family-signals-candidates-label">Alternative Candidates</p>
              {candidates.map((c, i) => {
                const candMeta = METHOD_META[c.source] || METHOD_META.none
                return (
                  <div key={i} className="family-signals-candidate-row">
                    <span className="family-signals-candidate-name">{c.family}</span>
                    {c.confidence != null && (
                      <span className="family-signals-candidate-conf">
                        {Math.round(c.confidence * 100)}%
                      </span>
                    )}
                    <span
                      className="family-signals-method-badge family-signals-method-badge-sm"
                      style={{
                        background: `${candMeta.color}22`,
                        color: candMeta.color,
                        borderColor: candMeta.color,
                      }}
                    >
                      {candMeta.label}
                    </span>
                  </div>
                )
              })}
            </div>
          )}

          {relatedCount != null && (
            <div className="family-signals-related">
              {relatedCount} known sample{relatedCount !== 1 ? 's' : ''} with this family
            </div>
          )}
        </div>
      )}
    </div>
  )
}

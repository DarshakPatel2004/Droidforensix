import { useState } from 'react'
import ThreatSummary from '../components/ThreatSummary'
import AttributionEvidence from '../components/AttributionEvidence'
import RelatedSamples from '../components/RelatedSamples'
import DissectionTabs from '../components/DissectionTabs'

const SECTIONS = [
  { id: 'summary', label: 'Threat Summary' },
  { id: 'attribution', label: 'Attribution' },
  { id: 'investigation', label: 'Investigation' },
  { id: 'related', label: 'Related' },
]

export default function SampleDetail({ sample, apiUrl, onSelectSample }) {
  const [activeSection, setActiveSection] = useState('summary')
  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  if (!sampleId) {
    return (
      <div className="empty-state">
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: 'var(--text-primary)' }}>No Sample Selected</div>
        <div style={{ fontSize: 13 }}>
          Upload or select a sample to view its analysis
        </div>
      </div>
    )
  }

  // RelatedSamples emits raw ids; normalize to the sample object contract.
  const handleRelatedSelect = (s) => onSelectSample?.(typeof s === 'string' ? { sampleId: s } : s)

  return (
    <div className="animate-fade-in">
      <div className="mb-4">
        <div className="section-title">Sample</div>
        <div className="heading-lg">
          {sample?.fileName || sample?.name || sampleId?.substring(0, 20)}
          <span className="text-mono" style={{ marginLeft: 12, fontSize: 12, color: 'var(--text-muted)', fontWeight: 400 }}>
            {sampleId?.substring(0, 16)}...
          </span>
        </div>
      </div>

      <div className="tab-bar" role="tablist" aria-label="Detail sections">
        {SECTIONS.map(s => (
          <button
            key={s.id}
            role="tab"
            aria-selected={activeSection === s.id}
            className={activeSection === s.id ? 'selected' : ''}
            onClick={() => setActiveSection(s.id)}
          >
            {s.label}
          </button>
        ))}
      </div>

      <div className="tab-body">
        {activeSection === 'summary' && (
          <ThreatSummary sampleId={sampleId} apiUrl={apiUrl} />
        )}

        {activeSection === 'attribution' && (
          <AttributionEvidence sampleId={sampleId} apiUrl={apiUrl} />
        )}

        {activeSection === 'investigation' && (
          <DissectionTabs sampleId={sampleId} apiUrl={apiUrl} />
        )}

        {activeSection === 'related' && (
          <RelatedSamples sampleId={sampleId} apiUrl={apiUrl} onSelect={handleRelatedSelect} />
        )}
      </div>
    </div>
  )
}

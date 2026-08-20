import { useState } from 'react'
import ThreatSummary from '../components/ThreatSummary'
import AttributionEvidence from '../components/AttributionEvidence'
import DissectionTabs from '../components/DissectionTabs'

const SECTIONS = [
  { id: 'summary', label: 'Threat Summary' },
  { id: 'attribution', label: 'Attribution' },
  { id: 'investigation', label: 'Investigation' },
]

export default function SampleDetail({ sample, apiUrl, onSelectSample }) {
  const [activeSection, setActiveSection] = useState('summary')
  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  if (!sampleId) {
    return (
      <div className="empty-state" style={{ padding: '4rem 2rem' }}>
        <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>No Sample Selected</div>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Upload or select a sample to view its analysis
        </div>
      </div>
    )
  }

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 4 }}>
          Sample
        </div>
        <div style={{ fontSize: 20, fontWeight: 700 }}>
          {sample?.fileName || sample?.name || sampleId?.substring(0, 20)}
          <span className="text-mono" style={{ marginLeft: 12, fontSize: 12, color: 'var(--text-muted)', fontWeight: 400 }}>
            {sampleId?.substring(0, 16)}...
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {SECTIONS.map(s => (
          <button
            key={s.id}
            onClick={() => setActiveSection(s.id)}
            style={{
              padding: '8px 18px', borderRadius: 8, border: 'none',
              fontWeight: 600, fontSize: 13, cursor: 'pointer',
              background: activeSection === s.id ? 'var(--accent-cyan)' : 'var(--bg-surface)',
              color: activeSection === s.id ? '#fff' : 'var(--text-secondary)',
              transition: 'all 0.15s',
            }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {activeSection === 'summary' && (
        <ThreatSummary sampleId={sampleId} apiUrl={apiUrl} />
      )}

      {activeSection === 'attribution' && (
        <AttributionEvidence sampleId={sampleId} apiUrl={apiUrl} />
      )}

      {activeSection === 'investigation' && (
        <DissectionTabs sampleId={sampleId} apiUrl={apiUrl} />
      )}
    </div>
  )
}

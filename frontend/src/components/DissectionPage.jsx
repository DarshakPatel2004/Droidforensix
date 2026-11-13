import { useState, useEffect } from 'react'
import './AnalysisView.css'
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'
import { DissectionSummaryTab } from './AnalysisView'
import ManifestView from './ManifestView'
import StateMessage from './ui/StateMessage'

const VIEWS = [
  { id: 'classes', label: 'Classes' },
  { id: 'summary', label: 'Summary' },
  { id: 'manifest', label: 'Manifest' },
]

export default function DissectionPage({ sample, apiUrl }) {
  const [selectedClass, setSelectedClass] = useState(null)
  const [showSource, setShowSource] = useState(false)
  const [view, setView] = useState('classes')

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  // Reset overlay state when the active sample changes so the previous
  // source view is not left open for a different sample.
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect */
    setSelectedClass(null)
    setShowSource(false)
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [sampleId])

  if (!sampleId) {
    return (
      <StateMessage tone="empty" title="Select a sample to view code dissection." />
    )
  }

  return (
    <div className="dissection-page" style={{ position: 'relative', minHeight: '400px' }}>
      <div className="result-tabs" role="tablist" aria-label="Investigation views">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            role="tab"
            aria-selected={view === v.id}
            className={`tab-button ${view === v.id ? 'active' : ''}`}
            onClick={() => setView(v.id)}
          >
            {v.label}
          </button>
        ))}
      </div>
      {view === 'classes' && (
        <SmartDissection
          sample={sample}
          apiUrl={apiUrl}
          onSelectClass={(name) => {
            setSelectedClass(name)
            setShowSource(true)
          }}
        />
      )}
      {view === 'summary' && <DissectionSummaryTab sampleId={sampleId} apiUrl={apiUrl} />}
      {view === 'manifest' && <ManifestView sample={sample} apiUrl={apiUrl} />}
      {showSource && (
        <div className="source-overlay">
          <div className="source-overlay-header">
            <h4 className="source-class-name text-mono">{selectedClass}</h4>
            <button
              className="source-close-button"
              onClick={() => {
                setShowSource(false)
                setSelectedClass(null)
              }}
              aria-label="Close source view"
            >
              Close
            </button>
          </div>
          <div className="source-overlay-content">
            <ClassSourceViewer
              sampleId={sampleId}
              className={selectedClass}
              apiUrl={apiUrl}
            />
          </div>
        </div>
      )}
    </div>
  )
}

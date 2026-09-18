import { useState, useEffect } from 'react'
import './AnalysisView.css'
import SmartDissection from './SmartDissection'
import ClassSourceViewer from './ClassSourceViewer'

export default function DissectionPage({ sample, apiUrl }) {
  const [selectedClass, setSelectedClass] = useState(null)
  const [showSource, setShowSource] = useState(false)

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
      <div className="analysis-idle">
        <p>Select a sample to view code dissection.</p>
      </div>
    )
  }

  return (
    <div className="dissection-page" style={{ position: 'relative', minHeight: '400px' }}>
      <SmartDissection
        sample={sample}
        apiUrl={apiUrl}
        onSelectClass={(name) => {
          setSelectedClass(name)
          setShowSource(true)
        }}
      />
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

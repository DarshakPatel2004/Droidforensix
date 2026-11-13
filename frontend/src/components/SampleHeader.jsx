import { useEffect, useState } from 'react'
import { apiFetch } from '../api/client'

const EXPORT_FORMATS = [
  { format: 'csv', label: 'CSV' },
  { format: 'stix', label: 'STIX' },
  { format: 'yara', label: 'YARA' },
  { format: 'suricata', label: 'Suricata' },
]

// Header above the tabs: name, family, analysis status, analyst status, and exports once analysis is complete.
export default function SampleHeader({ sample, status, ready, apiUrl }) {
  const sampleId = sample.sha256 || sample.sampleId
  const [analystStatus, setAnalystStatus] = useState(null)

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`)
      .then((body) => { if (!cancelled) setAnalystStatus(body.status) })
      .catch(() => { if (!cancelled) setAnalystStatus('unavailable') })
    return () => { cancelled = true }
  }, [sampleId])

  const family = sample.family && sample.family !== 'unknown' ? sample.family : 'No family match'

  return (
    <header className="sample-header">
      <div>
        <h1 className="sample-header-name">{sample.fileName || sampleId}</h1>
        <div className="sample-header-meta">
          <span>Family: {family}</span>
          <span>Analysis: {status}</span>
          <span>Analyst: {analystStatus ?? '…'}</span>
        </div>
      </div>
      {ready && (
        <div className="sample-header-exports" aria-label="Exports">
          {EXPORT_FORMATS.map(({ format, label }) => (
            <a
              key={format}
              href={`${apiUrl}/api/sample/${encodeURIComponent(sampleId)}/threat-intel/export/${format}`}
              download
            >
              {label}
            </a>
          ))}
        </div>
      )}
    </header>
  )
}

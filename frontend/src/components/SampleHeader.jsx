import { useEffect, useState } from 'react'
import { apiFetch } from '../api/client'

const EXPORT_FORMATS = [
  { format: 'csv', label: 'CSV' },
  { format: 'stix', label: 'STIX' },
  { format: 'yara', label: 'YARA' },
  { format: 'suricata', label: 'Suricata' },
]

// Case-file header above the tabs: identity, verdict facts, and exports once analysis is complete.
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

  const family = sample.family && sample.family !== 'unknown' ? sample.family : 'Unattributed'

  return (
    <header className="case-header">
      <div className="case-header-top">
        <p className="case-eyebrow">Case file <span>{sampleId?.slice(0, 16)}</span></p>
        {ready && (
          <nav className="case-exports" aria-label="Exports">
            <span>Export</span>
            {EXPORT_FORMATS.map(({ format, label }) => (
              <a
                key={format}
                href={`${apiUrl}/api/sample/${encodeURIComponent(sampleId)}/threat-intel/export/${format}`}
                download
              >
                {label}
              </a>
            ))}
          </nav>
        )}
      </div>
      <h1 className="case-name">{sample.fileName || sampleId}</h1>
      <dl className="case-facts">
        <div>
          <dt>Family</dt>
          <dd>{family}</dd>
        </div>
        <div>
          <dt>Analysis</dt>
          <dd>{status}</dd>
        </div>
        <div>
          <dt>Analyst</dt>
          <dd>{analystStatus ?? '…'}</dd>
        </div>
      </dl>
    </header>
  )
}

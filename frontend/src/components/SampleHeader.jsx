import { useEffect, useState } from 'react'
import { apiFetch } from '../api/client'

const EXPORT_FORMATS = [
  { format: 'csv', label: 'CSV' },
  { format: 'stix', label: 'STIX' },
  { format: 'yara', label: 'YARA' },
  { format: 'suricata', label: 'Suricata' },
]

const SEVERITY_CLASS = { critical: 'sev-high', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }

// Sample header: identity, the four facts the analyst needs before opening a tab, and exports once complete.
export default function SampleHeader({ sample, status, ready, apiUrl }) {
  const sampleId = sample.sha256 || sample.sampleId
  const [analystStatus, setAnalystStatus] = useState(null)
  const [attribution, setAttribution] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/analyst-state`)
      .then((body) => { if (!cancelled) setAnalystStatus(body.status) })
      .catch(() => { if (!cancelled) setAnalystStatus('unavailable') })
    if (ready) {
      apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/attribution`)
        .then((body) => { if (!cancelled) setAttribution(body) })
        .catch(() => { if (!cancelled) setAttribution({ error: true }) })
    }
    return () => { cancelled = true }
  }, [sampleId, ready])

  const copyHash = async () => {
    try {
      await navigator.clipboard.writeText(sampleId)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  const severity = sample.severity && sample.severity !== 'unknown' ? sample.severity : null
  const verdict = severity ? `${severity}${sample.risk_score != null ? ` · ${sample.risk_score}/100` : ''}` : 'Not yet scored'
  const familyName = attribution?.family && attribution.family !== 'unknown' ? attribution.family : null
  const confidence = attribution?.confidence != null ? `${Math.round(attribution.confidence * 100)}% confidence` : null
  const family = attribution?.error ? 'Attribution unavailable' : familyName ? `${familyName}${confidence ? ` · ${confidence}` : ''}` : ready ? 'No family match' : '—'

  return (
    <header className="sample-head">
      <div className="sample-head-top">
        <div className="sample-head-id">
          <h1 className="sample-head-name">{sample.fileName || sampleId}</h1>
          <div className="sample-head-hash">
            <code title={sampleId}>{sampleId}</code>
            <button type="button" onClick={copyHash} aria-label="Copy SHA-256">{copied ? 'Copied' : 'Copy'}</button>
          </div>
        </div>
        {ready && (
          <nav className="sample-head-export" aria-label="Exports">
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
      <dl className="sample-facts">
        <div>
          <dt>Analysis</dt>
          <dd>{status || '—'}</dd>
        </div>
        <div>
          <dt>Verdict</dt>
          <dd className={severity ? SEVERITY_CLASS[severity] : undefined}>{verdict}</dd>
        </div>
        <div>
          <dt>Family</dt>
          <dd>{family}</dd>
        </div>
        <div>
          <dt>Analyst status</dt>
          <dd>{analystStatus ?? '…'}</dd>
        </div>
      </dl>
    </header>
  )
}

import { useState, useEffect, useCallback, useRef } from 'react'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import '../styles/ThreatIntelView.css'

const API_URL = 'http://localhost:8000'

const DEFAULT_ICON = L.divIcon({
  className: 'custom-marker',
  html: '<div class="marker-dot"></div>',
  iconSize: [16, 16],
  iconAnchor: [8, 8],
  popupAnchor: [0, -10],
})

export default function ThreatIntelView({ sample, apiUrl }) {
  const [threatData, setThreatData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId

  const fetchThreatIntel = useCallback(async () => {
    if (!sampleId) return
    try {
      setLoading(true)
      const response = await fetch(`${apiUrl || API_URL}/api/sample/${sampleId}/threat-intel`)
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setThreatData(data)
      setError(null)
    } catch (err) {
      setError('Threat intelligence data not available: ' + err.message)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [sampleId, apiUrl])

  useEffect(() => {
    if (!sample) return
    fetchThreatIntel() // eslint-disable-line react-hooks/set-state-in-effect
  }, [sample, fetchThreatIntel])

  if (!sample) {
    return (
      <div className="state-container">
        <span className="state-icon">🌐</span>
        <h3 className="state-title">No sample selected</h3>
        <p className="state-description">Analyze an APK first to view Phase 2 threat intelligence enrichment.</p>
      </div>
    )
  }

  if (loading) {
    return <ThreatIntelLoading />
  }

  if (error) {
    return (
      <div className="state-container">
        <span className="state-icon">🛰</span>
        <h3 className="state-title">Threat Intelligence</h3>
        <p className="state-description">Phase 2 enrichment is not available for this sample. Ensure analysis completed successfully.</p>
      </div>
    )
  }

  if (!threatData) {
    return (
      <div className="state-container">
        <span className="state-icon">📭</span>
        <h3 className="state-title">No data available</h3>
        <p className="state-description">No threat intelligence data was returned for this sample.</p>
      </div>
    )
  }

  const dns = threatData.dns || {}
  const classification = threatData.classification || {}
  const geoIps = threatData.ips_geolocated || []
  const c2s = threatData.c2s || []
  const family = threatData.family || null

  const activeRate = Math.round((((dns.active || 0) + (dns.likely_active || 0)) / Math.max(c2s.length, 1)) * 100)

  return (
    <div className="threat-intel-view view-wrapper">
      <div className="threat-header card">
        <h2>Threat Intelligence Dashboard</h2>
        <p>Phase 2 enrichment: C2 verification, geo-location, and classification</p>
      </div>

      <div className="threat-stats">
        <StatCard value={c2s.length} label="Total C2 Indicators" color="rose" />
        <StatCard value={geoIps.length} label="IPs Geo-Located" color="cyan" />
        <StatCard value={`${activeRate}%`} label="Active C2 Rate" color="amber" />
        <StatCard value={classification.malicious || 0} label="Malicious C2s" color="emerald" />
      </div>

      {family && <FamilyCard family={family} />}

      <div className="threat-grid">
        <div className="threat-card card">
          <h3 className="section-title">DNS Verification Status</h3>
          <div className="dns-grid">
            <DnsStat value={dns.active || 0} label="Active" color="emerald" />
            <DnsStat value={dns.likely_active || 0} label="Likely Active" color="amber" />
            <DnsStat value={dns.dead || 0} label="Dead" color="rose" />
          </div>
        </div>

        <div className="threat-card card">
          <h3 className="section-title">C2 Classification</h3>
          <ClassificationBars classification={classification} total={c2s.length} />
        </div>
      </div>

      <div className="threat-card card c2-list-card">
        <h3 className="section-title">C2 Indicators ({c2s.length})</h3>
        {c2s.length === 0 ? (
          <p className="empty-state">No C2 indicators detected.</p>
        ) : (
          <div className="c2-list-wrap">
            <table className="c2-list-table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Details</th>
                  <th>Status</th>
                  <th>Classification</th>
                </tr>
              </thead>
              <tbody>
                {c2s.map((c2, idx) => (
                  <C2Row key={c2.c2_id || idx} c2={c2} geoIps={geoIps} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="threat-card card">
        <h3 className="section-title">Geographic Distribution</h3>
        {geoIps.length === 0 ? (
          <p className="empty-state">No geo-located IPs available</p>
        ) : (
          <div className="geo-layout">
            <div className="geo-map">
              <MapContainer
                center={[20, 0]}
                zoom={2}
                scrollWheelZoom={true}
                style={{ width: '100%', height: '100%', minHeight: '300px' }}
                zoomControl={false}
              >
                <TileLayer
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                <MapBoundsUpdater markers={geoIps.filter(ip => ip.latitude != null && ip.longitude != null)} />
                {geoIps.filter(ip => ip.latitude != null && ip.longitude != null).map((ip, idx) => (
                  <Marker key={idx} position={[ip.latitude, ip.longitude]} icon={DEFAULT_ICON}>
                    <Popup>
                      <strong>{ip.ip}</strong><br />
                      {ip.country}{ip.isp ? <><br />{ip.isp}</> : null}
                    </Popup>
                  </Marker>
                ))}
              </MapContainer>
            </div>
            <div className="geo-table-wrap">
              <table className="geo-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Type</th>
                    <th>Country</th>
                    <th>Region</th>
                    <th>ISP / Organization</th>
                    <th>Coordinates</th>
                  </tr>
                </thead>
                <tbody>
                  {geoIps.map((ip, idx) => {
                    const ipType = ip.ip_type || 'public'
                    const isPrivate = ipType === 'private' || ipType === 'loopback'
                    const ispLabel = ip.isp || ip.org || '-'
                    const asnLabel = ip.as || ''
                    return (
                      <tr key={idx} className={isPrivate ? 'geo-row-warn' : ''}>
                        <td className="text-mono">{ip.ip}</td>
                        <td>
                          <span className={`ip-type-badge ip-type-${ipType}`}>{ipType}</span>
                        </td>
                        <td>{ip.country}</td>
                        <td>{ip.region || '-'}</td>
                        <td>
                          <span className="isp-name">{ispLabel}</span>
                          {asnLabel && <span className="asn-name">{asnLabel}</span>}
                        </td>
                        <td className="text-mono">
                          {ip.latitude !== undefined && ip.latitude !== null && ip.longitude !== undefined && ip.longitude !== null
                            ? `${ip.latitude.toFixed(2)}, ${ip.longitude.toFixed(2)}`
                            : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      <PdfExportSection sampleId={sampleId} apiUrl={apiUrl || API_URL} />
    </div>
  )
}

function C2Row({ c2, geoIps }) {
  const indicator = c2.domain || c2.ip || 'Unknown'
  const detail = [c2.protocol, c2.port, c2.path].filter(Boolean).join(' · ') || '—'
  const status = normalizeStatus(c2.status)
  const classification = normalizeClassification(c2.classification)

  const resolvedIps = c2.live_dns?.ips || []
  const geo = geoIps.find(g => g.ip === c2.ip || resolvedIps.includes(g.ip))
  const country = geo?.country
  const ispLabel = geo?.isp || geo?.org || ''

  return (
    <tr>
      <td className="c2-indicator">
        <span className="c2-name text-mono" title={indicator}>{indicator}</span>
        {country && <span className="c2-country">{country}</span>}
        {geo?.ip_type && geo.ip_type !== 'public' && (
          <span className={`ip-type-badge ip-type-${geo.ip_type}`} style={{ marginLeft: '0.4rem' }}>{geo.ip_type}</span>
        )}
        {ispLabel && <span className="c2-isp">{ispLabel}</span>}
        {resolvedIps.length > 0 && c2.domain && (
          <div className="c2-resolved-ips" style={{ fontSize: '0.72rem', marginTop: '0.2rem', color: '#888' }}>
            Resolved: {resolvedIps.join(', ')}
          </div>
        )}
      </td>
      <td className="c2-detail text-mono" title={detail}>{detail}</td>
      <td><StatusBadge status={status} /></td>
      <td><ClassificationBadge classification={classification} /></td>
    </tr>
  )
}

function normalizeStatus(status) {
  const s = String(status || '').toLowerCase()
  if (s === 'active') return 'active'
  if (s === 'likely_active' || s === 'likely active') return 'likely_active'
  if (s === 'dead' || s === 'historical') return 'dead'
  return 'unknown'
}

function normalizeClassification(label) {
  const c = String(label || '').toLowerCase()
  if (c === 'malicious') return 'malicious'
  if (c === 'suspicious') return 'suspicious'
  if (c === 'benign') return 'benign'
  return 'unknown'
}

function StatusBadge({ status }) {
  const config = {
    active: { label: 'Active', color: 'emerald' },
    likely_active: { label: 'Likely Active', color: 'amber' },
    dead: { label: 'Dead', color: 'rose' },
    unknown: { label: 'Unknown', color: 'slate' },
  }
  const { label, color } = config[status] || config.unknown
  return <span className={`badge badge-${color}`}>{label}</span>
}

function ClassificationBadge({ classification }) {
  const config = {
    malicious: { label: 'Malicious', color: 'rose' },
    suspicious: { label: 'Suspicious', color: 'amber' },
    benign: { label: 'Benign', color: 'emerald' },
    unknown: { label: 'Unknown', color: 'slate' },
  }
  const { label, color } = config[classification] || config.unknown
  return <span className={`badge badge-${color}`}>{label}</span>
}

function StatCard({ value, label, color }) {
  return (
    <div className={`stat-card stat-${color}`}>
      <span className="stat-card-value">{value}</span>
      <span className="stat-card-label">{label}</span>
    </div>
  )
}

const METHOD_LABELS = {
  ground_truth: 'Ground Truth',
  yara: 'YARA',
  signature: 'Signature',
  llm: 'LLM',
  none: 'No Match',
  error: 'Error',
}

function FamilyCard({ family }) {
  const name = family.family || 'unknown'
  const isUnknown = name.toLowerCase() === 'unknown'
  const confidence = Math.round((family.confidence || 0) * 100)
  const method = family.method || 'none'
  const methodLabel = METHOD_LABELS[method] || method
  const candidates = (family.candidates || []).filter(c => c.family && c.family.toLowerCase() !== name.toLowerCase())

  return (
    <div className="threat-card card family-card">
      <div className="family-head">
        <div className="family-id">
          <span className="family-eyebrow">Malware Family</span>
          <span className={`family-name ${isUnknown ? 'family-unknown' : ''}`}>{name}</span>
          {family.reasoning && <span className="family-reasoning">{family.reasoning}</span>}
        </div>
        <div className="family-meta">
          <span className={`family-method method-${method}`}>{methodLabel}</span>
          {!isUnknown && (
            <div className="family-confidence">
              <div className="family-confidence-track">
                <div className="family-confidence-bar" style={{ width: `${confidence}%` }}></div>
              </div>
              <span className="family-confidence-value">{confidence}% confidence</span>
            </div>
          )}
        </div>
      </div>

      {candidates.length > 0 && (
        <div className="family-candidates">
          <span className="family-candidates-title">Other candidates</span>
          <div className="family-candidate-list">
            {candidates.map((c, idx) => (
              <span key={idx} className="family-candidate" title={c.reasoning || ''}>
                {c.family}
                <span className="family-candidate-src">{METHOD_LABELS[c.source] || c.source}</span>
                <span className="family-candidate-conf">{Math.round((c.confidence || 0) * 100)}%</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function DnsStat({ value, label, color }) {
  const num = value === undefined || value === null ? 0 : value
  return (
    <div className={`dns-stat dns-${color}`}>
      <span className={`dns-stat-value ${num === 0 ? 'empty' : ''}`}>{num}</span>
      <span className="dns-stat-label">{label}</span>
    </div>
  )
}

function ClassificationBars({ classification, total }) {
  const items = [
    { key: 'benign', label: 'Benign (SDK)', color: 'emerald' },
    { key: 'suspicious', label: 'Suspicious', color: 'amber' },
    { key: 'malicious', label: 'Malicious', color: 'rose' },
  ]

  return (
    <div className="classification-list">
      {items.map(item => {
        const value = classification[item.key] || 0
        const pct = total ? (value / total) * 100 : 0
        return (
          <div key={item.key} className="classification-row">
            <span className={`classification-label classification-${item.color}`}>{item.label}</span>
            <div className="classification-track">
              <div className={`classification-bar classification-${item.color}`} style={{ width: `${pct}%` }}></div>
            </div>
            <span className="classification-value">{value}</span>
          </div>
        )
      })}
      <div className="classification-total">Total C2s: {total}</div>
    </div>
  )
}

function PdfExportSection({ sampleId, apiUrl }) {
  const [state, setState] = useState('idle') // idle | generating | done | error
  const [mode, setMode] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const [showQuickOptions, setShowQuickOptions] = useState(false)
  // Selected sections for Quick PDF; defaults match the backend's defaults so
  // sending the object unchanged reproduces prior behaviour.
  const [sections, setSections] = useState({
    metadata: true,
    llm_assessment: true,
    obfuscation: true,
    c2_infrastructure: true,
    suspicious_methods: true,
  })

  const toggleSection = (key) => {
    setSections(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const startExport = async (exportMode) => {
    if (state === 'generating') return
    if (exportMode === 'full') {
      const confirmed = window.confirm(
        'Full export will generate LLM summaries for ALL suspicious methods.\n\n' +
        'This may take several minutes depending on your Ollama model speed.\n\n' +
        'Continue?'
      )
      if (!confirmed) return
    }

    const payload = { mode: exportMode }
    if (exportMode === 'quick') {
      payload.sections = sections
    }

    setState('generating')
    setMode(exportMode)
    setErrorMsg('')

    try {
      const res = await fetch(`${apiUrl}/api/sample/${sampleId}/report/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(err.detail || 'Export failed')
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      // Make the filename distinct when the Quick PDF has a non-default
      // section selection so multiple exports don't silently overwrite.
      let suffix = exportMode
      if (exportMode === 'quick') {
        const active = Object.entries(sections)
          .filter(([, v]) => v)
          .map(([k]) => k.split('_')[0])
        const allOn = active.length === quickOptions.length
        suffix = allOn ? 'quick' : `quick_${active.join('-') || 'cover'}`
      }
      a.download = `droidforensix_${sampleId.slice(0, 12)}_${suffix}.pdf`
      a.click()
      URL.revokeObjectURL(url)
      setState('done')
      setTimeout(() => setState('idle'), 3000)
    } catch (err) {
      setErrorMsg(err.message)
      setState('error')
      setTimeout(() => setState('idle'), 5000)
    }
  }

  const quickOptions = [
    { key: 'metadata',           label: 'Sample Metadata' },
    { key: 'llm_assessment',      label: 'LLM Threat Assessment' },
    { key: 'obfuscation',         label: 'Obfuscation Analysis' },
    { key: 'c2_infrastructure',   label: 'C2 Infrastructure' },
    { key: 'suspicious_methods',  label: 'Suspicious Methods' },
  ]

  return (
    <div className="threat-card card">
      <h3 className="section-title">Export Report</h3>
      <p className="export-description">
        Generate a forensic PDF report including LLM method analysis, C2 indicators, severity assessment, and obfuscation findings.
      </p>

      <div className="pdf-export-buttons">
        <button
          className={`pdf-export-btn pdf-export-quick ${state === 'generating' && mode === 'quick' ? 'generating' : ''}`}
          onClick={() => startExport('quick')}
          disabled={state === 'generating'}
          title="Top 30 suspicious methods with LLM summaries — fast"
        >
          {state === 'generating' && mode === 'quick' ? (
            <><span className="pdf-spinner" /> Generating…</>
          ) : (
            <><span className="pdf-icon">📄</span> Export PDF Report</>
          )}
          <span className="pdf-badge">Top 30 methods</span>
        </button>

        <button
          className={`pdf-export-btn pdf-export-full ${state === 'generating' && mode === 'full' ? 'generating' : ''}`}
          onClick={() => startExport('full')}
          disabled={state === 'generating'}
          title="All suspicious methods — may take several minutes"
        >
          {state === 'generating' && mode === 'full' ? (
            <><span className="pdf-spinner" /> Generating… (this may take a while)</>
          ) : (
            <><span className="pdf-icon">📋</span> Full Export PDF</>
          )}
          <span className="pdf-badge pdf-badge-warning">⏱ May take minutes</span>
        </button>
      </div>

      <details className="quick-pdf-options" open={showQuickOptions}
        onToggle={(e) => setShowQuickOptions(e.target.open)}>
        <summary>Customize Quick PDF sections</summary>
        <p className="quick-pdf-options-hint">
          Choose which sections appear in the Quick PDF. Cover page is always included.
        </p>
        <div className="quick-pdf-section-list">
          {quickOptions.map(opt => (
            <label key={opt.key} className="quick-pdf-section-item">
              <input
                type="checkbox"
                checked={sections[opt.key]}
                onChange={() => toggleSection(opt.key)}
                disabled={state === 'generating'}
              />
              <span>{opt.label}</span>
            </label>
          ))}
        </div>
      </details>

      {state === 'done' && (
        <p className="pdf-status pdf-status-ok">✓ Report downloaded successfully</p>
      )}
      {state === 'error' && (
        <p className="pdf-status pdf-status-error">✗ {errorMsg}</p>
      )}
    </div>
  )
}

function MapBoundsUpdater({ markers }) {
  const map = useMap()
  const fitted = useRef(false)

  useEffect(() => {
    if (markers.length === 0 || fitted.current) return
    const bounds = L.latLngBounds(markers.map(m => [m.latitude, m.longitude]))
    if (bounds.isValid()) {
      map.fitBounds(bounds, { padding: [60, 60], maxZoom: 10 })
      fitted.current = true
    }
  }, [markers, map])

  return null
}

function ThreatIntelLoading() {
  const phases = [
    'Resolving C2 domains',
    'Checking DNS liveness',
    'Classifying indicators',
    'Identifying malware family',
    'Building geo map',
  ]
  const [phase, setPhase] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setPhase(p => (p + 1) % phases.length)
    }, 1200)
    return () => clearInterval(interval)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const progress = Math.round(((phase + 1) / phases.length) * 100)

  return (
    <div className="threat-loading card">
      <div className="threat-loading-spinner"></div>
      <h3 className="threat-loading-title">Loading Threat Intelligence</h3>
      <p className="threat-loading-subtitle">Fetching C2 geo-location, DNS status, and classification data...</p>

      <div className="threat-loading-progress">
        <div className="threat-loading-progress-header">
          <span className="threat-loading-phase">{phases[phase]}</span>
          <span className="threat-loading-percent">{progress}%</span>
        </div>
        <div className="threat-loading-track">
          <div className="threat-loading-bar" style={{ width: `${progress}%` }}></div>
        </div>
      </div>

      <div className="threat-loading-skeleton">
        <div className="threat-skeleton-row"></div>
        <div className="threat-skeleton-row short"></div>
      </div>
    </div>
  )
}




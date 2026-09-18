import '../styles/ThreatSynthesisPanel.css'

const SIGNAL_LABELS = {
  binary_packing: 'Binary Packing',
  reflective_calls: 'Reflective Calls',
  reflective_permission_mismatch: 'Reflective Permission Mismatch',
  c2_endpoints: 'C2 Endpoints',
  high_entropy_strings: 'High-Entropy Strings',
  native_obfuscation: 'Native Obfuscation',
  certificate_anomaly: 'Certificate Anomaly',
}

const SIGNAL_COLORS = {
  binary_packing: '#f97316',
  reflective_calls: '#ef4444',
  reflective_permission_mismatch: '#a855f7',
  c2_endpoints: '#ec4899',
  high_entropy_strings: '#f59e0b',
  native_obfuscation: '#8b5cf6',
  certificate_anomaly: '#64748b',
}

const LEVEL_CLASS = {
  critical: 'badge-rose',
  high: 'badge-rose',
  medium: 'badge-amber',
  low: 'badge-emerald',
  none: 'badge-slate',
  unknown: 'badge-slate',
}

function levelBadge(level) {
  return LEVEL_CLASS[level] || 'badge-slate'
}

export default function ThreatSynthesisPanel({ synthesis }) {
  if (!synthesis) {
    return (
      <div className="tab-panel">
        <div className="card" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          <p>No threat synthesis data available</p>
        </div>
      </div>
    )
  }

  const { zero_day_risk_score = 0, risk_level = 'none', contributing_signals = [] } = synthesis
  const sorted = [...contributing_signals].sort((a, b) => b.contribution - a.contribution)

  return (
    <div className="tab-panel threat-synthesis-panel">
      <div className="card threat-synthesis-score-hero">
        <div className="threat-synthesis-score-left">
          <h3>Zero-Day Risk Score</h3>
          <span className="threat-score-value">{zero_day_risk_score}<small>/100</small></span>
        </div>
        <div className="threat-synthesis-score-right">
          <span className={`badge ${levelBadge(risk_level)}`} style={{ fontSize: '0.85rem', padding: '4px 12px' }}>
            {risk_level.toUpperCase()}
          </span>
        </div>
      </div>

      {sorted.length > 0 && (
        <div className="card">
          <h3>Contributing Signals ({sorted.length})</h3>
          <div className="threat-signal-list">
            {sorted.map((s, i) => (
              <div key={i} className="threat-signal-row">
                <div className="threat-signal-bar-track">
                  <div
                    className="threat-signal-bar-fill"
                    style={{
                      width: `${Math.min(100, (s.contribution / 20) * 100)}%`,
                      backgroundColor: SIGNAL_COLORS[s.signal] || '#64748b',
                    }}
                  />
                </div>
                <span className="threat-signal-name">{SIGNAL_LABELS[s.signal] || s.signal}</span>
                <span className="threat-signal-contribution">+{s.contribution}</span>
                <span className="threat-signal-detail">{s.detail || ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {sorted.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
          <p>No threat signals detected</p>
        </div>
      )}
    </div>
  )
}

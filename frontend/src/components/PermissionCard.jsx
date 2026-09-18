const RISK_STYLES = {
  dangerous: { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)' },
  signature: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.1)' },
  normal: { color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.1)' },
}

export default function PermissionCard({ name, label, protectionLevel, description }) {
  const style = RISK_STYLES[protectionLevel] || RISK_STYLES.normal
  return (
    <div className="card" style={{
      padding: '10px 14px', display: 'flex', alignItems: 'center',
      justifyContent: 'space-between', gap: 12,
    }}>
      <div>
        <div className="text-mono" style={{ fontSize: 13 }}>{name}</div>
        {(label || description) && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {label || description}
          </div>
        )}
      </div>
      <span className="badge" style={{ background: style.bg, color: style.color, flexShrink: 0 }}>
        {protectionLevel || 'normal'}
      </span>
    </div>
  )
}

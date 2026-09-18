const LEVELS = {
  CRITICAL: { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.15)' },
  HIGH: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.15)' },
  MEDIUM: { color: 'var(--accent-cyan)', bg: 'rgba(6,182,212,0.15)' },
  LOW: { color: 'var(--accent-emerald)', bg: 'rgba(16,185,129,0.15)' },
  INFO: { color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.15)' },
  UNKNOWN: { color: 'var(--text-muted)', bg: 'rgba(148,163,184,0.08)' },
}

export default function ThreatBadge({ level, label, size = 'md' }) {
  const key = (level || 'UNKNOWN').toUpperCase()
  const cfg = LEVELS[key] || LEVELS.UNKNOWN
  const fontSize = size === 'sm' ? 9 : size === 'lg' ? 13 : 11
  const padding = size === 'sm' ? '2px 8px' : size === 'lg' ? '6px 14px' : '4px 10px'
  const text = label || key

  return (
    <span className="text-mono" style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding, borderRadius: 999, fontSize, fontWeight: 600,
      background: cfg.bg, color: cfg.color,
      lineHeight: 1.3,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0 }} />
      {text}
    </span>
  )
}

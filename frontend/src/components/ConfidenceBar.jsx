

const RISK_COLORS = {
  CRITICAL: { bar: '#f43f5e', bg: 'rgba(244,63,94,0.15)', text: '#f43f5e' },
  HIGH: { bar: '#f59e0b', bg: 'rgba(245,158,11,0.15)', text: '#f59e0b' },
  MEDIUM: { bar: '#06b6d4', bg: 'rgba(6,182,212,0.15)', text: '#06b6d4' },
  LOW: { bar: '#10b981', bg: 'rgba(16,185,129,0.15)', text: '#10b981' },
}

export default function ConfidenceBar({ value, label, color, showLabel = true, size = 'md' }) {
  const clamped = Math.max(0, Math.min(100, Math.round(value * 100)))
  const barColor = color || (clamped >= 75 ? RISK_COLORS.CRITICAL.bar
    : clamped >= 50 ? RISK_COLORS.HIGH.bar
    : clamped >= 25 ? RISK_COLORS.MEDIUM.bar
    : RISK_COLORS.LOW.bar)
  const bgColor = color ? `${color}22` : (clamped >= 75 ? RISK_COLORS.CRITICAL.bg
    : clamped >= 50 ? RISK_COLORS.HIGH.bg
    : clamped >= 25 ? RISK_COLORS.MEDIUM.bg
    : RISK_COLORS.LOW.bg)
  const textColor = color || (clamped >= 75 ? RISK_COLORS.CRITICAL.text
    : clamped >= 50 ? RISK_COLORS.HIGH.text
    : clamped >= 25 ? RISK_COLORS.MEDIUM.text
    : RISK_COLORS.LOW.text)

  const height = size === 'sm' ? 6 : size === 'lg' ? 14 : 10

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      {showLabel && label && (
        <span style={{ fontSize: 13, color: 'var(--text-secondary)', minWidth: 120, whiteSpace: 'nowrap' }}>
          {label}
        </span>
      )}
      <div style={{ flex: 1, position: 'relative' }}>
        <div style={{
          height, borderRadius: 6, background: bgColor,
          overflow: 'hidden', position: 'relative',
        }}>
          <div style={{
            width: `${clamped}%`, height: '100%', borderRadius: 6,
            background: barColor, transition: 'width 0.5s ease-out',
            boxShadow: `0 0 8px ${barColor}44`,
          }} />
        </div>
      </div>
      <span style={{
        fontSize: 13, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace",
        color: textColor, minWidth: 36, textAlign: 'right',
      }}>
        {clamped}%
      </span>
    </div>
  )
}

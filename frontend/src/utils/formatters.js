export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '\u2014'
  if (seconds === 0) return '0s'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  const parts = []
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  if (s > 0) parts.push(`${s}s`)
  return parts.join(' ')
}

export function truncateHash(hash, len = 16) {
  if (!hash) return ''
  return hash.length > len ? `${hash.substring(0, len)}\u2026` : hash
}

export function formatTimestamp(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString()
}

export function riskColor(level) {
  const map = {
    CRITICAL: 'var(--accent-rose)',
    HIGH: 'var(--accent-amber)',
    MEDIUM: 'var(--accent-cyan)',
    LOW: 'var(--accent-emerald)',
  }
  return map[level] || 'var(--text-muted)'
}

export function riskBg(level) {
  const map = {
    CRITICAL: 'rgba(244,63,94,0.15)',
    HIGH: 'rgba(245,158,11,0.15)',
    MEDIUM: 'rgba(6,182,212,0.15)',
    LOW: 'rgba(16,185,129,0.15)',
  }
  return map[level] || 'rgba(148,163,184,0.1)'
}

export function severityFromScore(score) {
  if (score >= 75) return 'CRITICAL'
  if (score >= 50) return 'HIGH'
  if (score >= 25) return 'MEDIUM'
  return 'LOW'
}

export function entropyLabel(entropy) {
  if (entropy > 7) return { label: 'High', color: 'var(--accent-rose)' }
  if (entropy > 5) return { label: 'Moderate', color: 'var(--accent-amber)' }
  return { label: 'Normal', color: 'var(--accent-emerald)' }
}

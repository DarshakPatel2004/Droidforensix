const RISK_BADGE_COLORS = { critical: 'rose', high: 'rose', medium: 'amber', low: 'emerald', none: 'slate', unknown: 'slate' }

export function riskLevelBadgeClass(level) {
  return `badge-${RISK_BADGE_COLORS[level] || 'slate'}`
}

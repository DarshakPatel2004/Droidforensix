// Plain-language summaries of the nine deep-analysis checks, read from pipeline_result.json.
// "Finding" means the check reported something worth a look; "Clear" means it did not;
// "Unavailable" means the sample has no result for that check.

const finding = (line) => ({ tag: 'Finding', line })
const clear = (line) => ({ tag: 'Clear', line })

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`

export const DEEP_CHECKS = [
  {
    key: 'binary_packing',
    title: 'Binary packing',
    summarise: (d) => (d.packing_detected ? finding('Packer detected') : clear('No packer detected')),
  },
  {
    key: 'string_clustering',
    title: 'String clustering',
    summarise: (d) => (d.total_clusters > 0
      ? finding(plural(d.total_clusters, 'high-entropy string cluster'))
      : clear('No high-entropy string clusters')),
  },
  {
    key: 'reflective_tracing',
    title: 'Reflective tracing',
    summarise: (d) => (d.total_reflective_calls > 0
      ? finding(plural(d.total_reflective_calls, 'reflective call'))
      : clear('No reflective calls')),
  },
  {
    key: 'native_elf_analysis',
    title: 'Native libraries',
    summarise: (d) => (d.total_libraries > 0
      ? finding(plural(d.total_libraries, 'native library file'))
      : clear('No native libraries')),
  },
  {
    key: 'network_protocols',
    title: 'Network endpoints',
    summarise: (d) => {
      const flagged = (d.total_c2 || 0) + (d.total_suspicious || 0)
      return flagged > 0
        ? finding(`${d.total_c2 || 0} C2 and ${d.total_suspicious || 0} suspicious endpoint(s)`)
        : clear('No endpoints classified')
    },
  },
  {
    key: 'permission_correlation',
    title: 'Permission use',
    summarise: (d) => (d.total_used > 0
      ? finding(`${d.total_used} of ${d.total_permissions} declared permission(s) used in code`)
      : clear(`${d.total_permissions || 0} declared, none seen used in code`)),
  },
  {
    key: 'certificate_analysis',
    title: 'Certificate',
    summarise: (d) => {
      if (d.known_bad || d.suspicious_issuer) return finding('Certificate flagged')
      if (!d.certificate_found) return clear('No certificate found')
      return clear(d.warnings?.[0] || 'Not known-bad')
    },
  },
  {
    key: 'family_clustering',
    title: 'Family clustering',
    summarise: (d) => (d.best_match
      ? finding('Matches a known cluster')
      : clear('No cluster match')),
  },
  {
    key: 'threat_synthesis',
    title: 'Zero-day risk',
    summarise: (d) => {
      const line = `Zero-day risk ${d.zero_day_risk_score ?? 0}/100`
      return ['medium', 'high', 'critical'].includes(d.risk_level) ? finding(line) : clear(line)
    },
  },
]

// Returns one { key, title, tag, line } per check, in the order of DEEP_CHECKS.
export function summarizeChecks(result) {
  return DEEP_CHECKS.map(({ key, title, summarise }) => {
    const data = result?.[key]
    if (!data || typeof data !== 'object') {
      return { key, title, tag: 'Unavailable', line: 'Not available for this sample' }
    }
    return { key, title, ...summarise(data) }
  })
}

const SEVERE_CHAIN_LEVELS = ['medium', 'high', 'critical']

// Short list of things an analyst should look at first, built from data already on the result.
// c2Count is the unique C2 indicator count from the threat summary.
export function needsAttention(result, c2Count = 0) {
  const items = []

  if (c2Count > 0) {
    items.push({ tag: 'C2', level: 'warn', text: `${plural(c2Count, 'unique C2 indicator')} found` })
  }

  const chains = (result?.threat_chains || []).filter((c) => SEVERE_CHAIN_LEVELS.includes(c.severity))
  if (chains.length > 0) {
    items.push({ tag: 'Chain', level: 'warn', text: `${plural(chains.length, 'threat chain')} at medium severity or higher` })
  }

  summarizeChecks(result)
    .filter((c) => c.tag === 'Finding')
    .forEach((c) => items.push({ tag: 'Check', level: 'warn', text: `${c.title}: ${c.line}` }))

  if (result?.needs_manual_review) {
    items.push({ tag: 'Review', level: 'info', text: 'Flagged for manual review' })
  }

  return items
}

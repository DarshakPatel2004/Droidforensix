import CheckCard from './CheckCard'
import { summarizeChecks } from '../utils/checkSummaries'

// The nine deep-analysis checks, one card each. No step numbers are shown.
export default function DeepAnalysis({ result }) {
  const checks = summarizeChecks(result)
  const findings = checks.filter((c) => c.tag === 'Finding').length

  return (
    <section aria-labelledby="deep-analysis-heading" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
        <h2 id="deep-analysis-heading" style={{ margin: 0, fontSize: 16 }}>Deep analysis</h2>
        <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          {findings} of {checks.length} found something
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
        {checks.map((c) => (
          <CheckCard key={c.key} title={c.title} tag={c.tag} line={c.line} />
        ))}
      </div>
    </section>
  )
}

import { useSampleData } from '../../hooks/useSampleData'
import { summarizeChecks, needsAttention } from '../../utils/checkSummaries'
import DeepAnalysis from '../DeepAnalysis'
import LoadingSpinner from '../LoadingSpinner'
import Panel from '../ui/Panel'

const toneStyle = { medium: 'var(--accent-amber)', high: 'var(--accent-rose)', critical: 'var(--accent-rose)', low: 'var(--accent-emerald)' }

function KpiTile({ label, value, unit = '', note, source, tone }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>
        {value}
        {unit && <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-muted)' }}>{unit}</span>}
      </div>
      <div style={{ fontSize: 12, fontWeight: 600, color: tone || 'var(--text-muted)' }}>{note}</div>
      <div style={{ fontSize: 11, color: 'var(--text-subtle)' }}>{source}</div>
    </div>
  )
}

// Analyst landing page for a finished sample: verdict figures, what needs attention, and the nine checks.
export default function OverviewTab({ sampleId }) {
  const result = useSampleData(sampleId, `/api/sample/${encodeURIComponent(sampleId)}`)
  const summary = useSampleData(sampleId, `/api/sample/${encodeURIComponent(sampleId)}/threat-summary`)
  // Family and confidence come from the attribution endpoint, the same source the Attribution tab shows.
  const attribution = useSampleData(sampleId, `/api/sample/${encodeURIComponent(sampleId)}/attribution`)

  if (result.error) return <div className="empty-state" role="alert">Could not load this sample: {result.error.message}</div>
  if (!result.data) return <LoadingSpinner message="Loading overview..." />

  const data = result.data
  const llm = data.llm_assessment || {}
  const obfuscation = data.obfuscation_analysis || {}
  const zeroDay = data.threat_synthesis?.zero_day_risk_score ?? null
  const c2Count = summary.data?.c2_count ?? 0
  const attention = needsAttention(data, c2Count)
  const findings = summarizeChecks(data).filter((c) => c.tag === 'Finding').length
  const family = attribution.data || {}

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <section aria-label="Key figures" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
        <KpiTile label="LLM risk" value={llm.risk_score ?? '—'} unit={llm.risk_score != null ? ' /100' : ''} note={llm.severity ?? 'not assessed'} source="from LLM assessment" tone={toneStyle[llm.severity]} />
        <KpiTile label="C2 indicators" value={summary.data ? c2Count : '—'} note="unique domains · not enriched" source="from static analysis" />
        <KpiTile label="Obfuscation" value={obfuscation.obfuscation_score ?? '—'} unit={obfuscation.obfuscation_score != null ? ' /100' : ''} note={obfuscation.obfuscation_level ?? 'not assessed'} source="from obfuscation analysis" tone={toneStyle[obfuscation.obfuscation_level]} />
        <KpiTile label="Zero-day risk" value={zeroDay ?? '—'} unit={zeroDay != null ? ' /100' : ''} note={zeroDay == null ? 'not assessed' : zeroDay > 0 ? 'Review' : 'No signals'} source="from threat synthesis" />
      </section>

      <section aria-labelledby="attention-heading" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <h2 id="attention-heading" style={{ margin: 0, fontSize: 16 }}>Needs your attention</h2>
        {attention.length === 0 ? (
          <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)' }}>Nothing flagged for review.</p>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {attention.map((item, i) => (
              <li key={i} style={{ display: 'flex', gap: 12, alignItems: 'baseline' }}>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 4, minWidth: 52, textAlign: 'center', flex: 'none', ...(item.level === 'warn' ? { background: 'var(--accent-amber-soft)', color: 'var(--accent-amber)' } : { background: 'var(--accent-cyan-soft)', color: 'var(--accent-cyan)' }) }}>
                  {item.tag}
                </span>
                <span style={{ fontSize: 14, color: 'var(--text-secondary)' }}>{item.text}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="attribution-heading" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 12, padding: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <h2 id="attribution-heading" style={{ margin: 0, fontSize: 16 }}>Attribution</h2>
        <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)' }}>
          {family.family && family.family !== 'unknown'
            ? `Matched to ${family.family} (${Math.round((family.confidence || 0) * 100)}% confidence). ${findings} of 9 checks found something.`
            : `No family match. ${findings} of 9 checks found something.`}
        </p>
      </section>

      <DeepAnalysis result={data} />

      <Panel title="All checks">
        <ul className="all-checks">
          {summarizeChecks(data).map((c) => (
            <li key={c.key}>
              <span className="all-checks-title">{c.title}</span>
              <span className={`all-checks-tag ${c.tag === 'Finding' ? 'tone-medium' : ''}`}>{c.tag}</span>
              <span className="all-checks-line">{c.line}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  )
}

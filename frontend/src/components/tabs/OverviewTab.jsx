import { useSampleData } from '../../hooks/useSampleData'
import { summarizeChecks, needsAttention } from '../../utils/checkSummaries'
import { riskLevelBadgeClass } from '../../utils/riskLevel'
import DeepAnalysis from '../DeepAnalysis'
import LoadingSpinner from '../LoadingSpinner'

const toneStyle = { medium: '#8a3b00', high: '#8a3b00', critical: '#8a3b00', low: '#11633a' }

function KpiTile({ label, value, unit = '', note, tone }) {
  return (
    <div style={{ background: 'var(--surface, #fff)', border: '1px solid var(--border, #e1e4ea)', borderRadius: 12, padding: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 12, color: 'var(--text-muted, #555b66)' }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700 }}>
        {value}
        {unit && <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-muted, #555b66)' }}>{unit}</span>}
      </div>
      <div style={{ fontSize: 12, fontWeight: 600, color: tone || 'var(--text-muted, #555b66)' }}>{note}</div>
    </div>
  )
}

// Analyst landing page for a finished sample: verdict figures, what needs attention, and the nine checks.
export default function OverviewTab({ sampleId }) {
  const result = useSampleData(sampleId, `/api/sample/${encodeURIComponent(sampleId)}`, { cached: false })
  const summary = useSampleData(sampleId, `/api/sample/${encodeURIComponent(sampleId)}/threat-summary`)

  if (result.error) return <div className="empty-state" role="alert">Could not load this sample: {result.error.message}</div>
  if (!result.data) return <LoadingSpinner message="Loading overview..." />

  const data = result.data
  const llm = data.llm_assessment || {}
  const obfuscation = data.obfuscation_analysis || {}
  const zeroDay = data.threat_synthesis?.zero_day_risk_score ?? 0
  const c2Count = summary.data?.c2_count ?? 0
  const attention = needsAttention(data, c2Count)
  const findings = summarizeChecks(data).filter((c) => c.tag === 'Finding').length
  const family = data.family_identification || {}

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      <section aria-label="Key figures" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
        <KpiTile label="LLM risk" value={llm.risk_score ?? 0} unit=" /100" note={llm.severity ?? 'unknown'} tone={toneStyle[llm.severity]} />
        <KpiTile label="C2 indicators" value={c2Count} note="unique · not enriched" />
        <KpiTile label="Obfuscation" value={obfuscation.obfuscation_score ?? 0} unit=" /100" note={obfuscation.obfuscation_level ?? 'low'} tone={toneStyle[obfuscation.obfuscation_level]} />
        <KpiTile label="Zero-day risk" value={zeroDay} unit=" /100" note={zeroDay > 0 ? 'Review' : 'No signals'} />
      </section>

      <section aria-labelledby="attention-heading" style={{ background: 'var(--surface, #fff)', border: '1px solid var(--border, #e1e4ea)', borderRadius: 12, padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <h2 id="attention-heading" style={{ margin: 0, fontSize: 16 }}>Needs your attention</h2>
        {attention.length === 0 ? (
          <p style={{ margin: 0, fontSize: 14 }}>Nothing flagged for review.</p>
        ) : (
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {attention.map((item, i) => (
              <li key={i} style={{ display: 'flex', gap: 12, alignItems: 'baseline' }}>
                <span className={riskLevelBadgeClass(item.level === 'warn' ? 'medium' : 'low')} style={{ fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 4, minWidth: 52, textAlign: 'center', flex: 'none' }}>
                  {item.tag}
                </span>
                <span style={{ fontSize: 14 }}>{item.text}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="attribution-heading" style={{ background: 'var(--surface, #fff)', border: '1px solid var(--border, #e1e4ea)', borderRadius: 12, padding: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <h2 id="attribution-heading" style={{ margin: 0, fontSize: 16 }}>Attribution</h2>
        <p style={{ margin: 0, fontSize: 14 }}>
          {family.family && family.family !== 'unknown'
            ? `Matched to ${family.family} (${Math.round((family.confidence || 0) * 100)}% confidence). ${findings} of 9 checks found something.`
            : `No family match. ${findings} of 9 checks found something.`}
        </p>
      </section>

      <DeepAnalysis result={data} />
    </div>
  )
}

// Verdict word plus score. The word is always shown, so colour is never the only signal.
const TONE = { critical: 'high', high: 'high', medium: 'medium', low: 'low' }

export default function VerdictChip({ severity, score }) {
  if (!severity || severity === 'unknown') return <span className="ui-verdict is-none">Not yet scored</span>
  const tone = TONE[severity] || 'none'
  return (
    <span className={`ui-verdict tone-${tone}`}>
      {severity}
      {score != null && <span className="ui-verdict-score"> {score}/100</span>}
    </span>
  )
}

// Label/value pairs in a single ruled row. Missing values render as the given placeholder, never as 0.
export default function FactStrip({ facts, placeholder = '—' }) {
  return (
    <dl className="ui-facts">
      {facts.map(({ label, value, tone }) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd className={tone ? `tone-${tone}` : undefined}>{value ?? placeholder}</dd>
        </div>
      ))}
    </dl>
  )
}

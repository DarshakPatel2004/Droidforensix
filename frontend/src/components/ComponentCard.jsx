export default function ComponentCard({ name, exported, intentFilters, type }) {
  return (
    <div className="card" style={{ padding: '10px 14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div className="text-mono" style={{ fontSize: 13, flex: 1 }}>{name}</div>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
          {type}
        </span>
        {exported !== undefined && (
          <span className={`badge ${exported ? 'amber' : 'emerald'}`}>
            {exported ? 'Exported' : 'Not Exported'}
          </span>
        )}
      </div>
      {intentFilters?.length > 0 && (
        <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {intentFilters.map((f, j) => (
            <span key={j} className="badge neutral" style={{ fontSize: 10 }}>{f}</span>
          ))}
        </div>
      )}
    </div>
  )
}

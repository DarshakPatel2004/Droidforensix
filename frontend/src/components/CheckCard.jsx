const TAG_STYLES = {
  Finding: { background: '#fde7d3', color: '#8a3b00' },
  Clear: { background: '#eceef2', color: '#3d424c' },
  Unavailable: { background: '#f4f4f4', color: '#6b7280' },
}

// One deep-analysis check: its name, a Finding/Clear tag, and a one-line result.
export default function CheckCard({ title, tag, line }) {
  return (
    <article
      aria-label={`${title}: ${tag}`}
      style={{
        background: 'var(--surface, #fff)',
        border: '1px solid var(--border, #e1e4ea)',
        borderRadius: 12,
        padding: 16,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <h3 style={{ margin: 0, fontSize: 15 }}>{title}</h3>
        <span style={{ fontSize: 11, fontWeight: 600, padding: '3px 8px', borderRadius: 999, flex: 'none', ...TAG_STYLES[tag] }}>
          {tag}
        </span>
      </div>
      <p style={{ margin: 0, fontSize: 13 }}>{line}</p>
    </article>
  )
}

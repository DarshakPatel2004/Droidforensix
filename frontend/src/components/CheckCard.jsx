const TAG_STYLES = {
  Finding: { background: 'var(--accent-amber-soft)', color: 'var(--accent-amber)' },
  Clear: { background: 'var(--bg-elevated)', color: 'var(--text-secondary)' },
  Unavailable: { background: 'var(--bg-surface)', color: 'var(--text-subtle)' },
}

// One deep-analysis check: its name, a Finding/Clear tag, and a one-line result.
export default function CheckCard({ title, tag, line }) {
  return (
    <article
      aria-label={`${title}: ${tag}`}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-color)',
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
      <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>{line}</p>
    </article>
  )
}

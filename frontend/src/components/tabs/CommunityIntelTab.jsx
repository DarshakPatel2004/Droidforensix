import { useState, useEffect, useCallback } from 'react'
/* eslint-disable react-hooks/set-state-in-effect */

const SOURCE_STYLES = {
  Reddit: { color: 'var(--accent-amber)', bg: 'rgba(245,158,11,0.1)' },
  'Hacker News': { color: 'var(--accent-rose)', bg: 'rgba(244,63,94,0.1)' },
  DuckDuckGo: { color: 'var(--accent-cyan)', bg: 'rgba(6,182,212,0.1)' },
}

function formatWhen(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const days = Math.floor((Date.now() - d.getTime()) / 86400000)
  if (days <= 0) return 'today'
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days}d ago`
  return d.toLocaleDateString()
}

export default function CommunityIntelTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(() => {
    if (!sampleId) return
    setLoading(true)
    setError(null)
    fetch(`${apiUrl}/api/sample/${sampleId}/community-intel`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e.message || 'Failed to load'); setLoading(false) })
  }, [sampleId, apiUrl])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="empty-state">Searching forums for community gossip...</div>
  if (error) return (
    <div>
      <div className="empty-state" style={{ color: 'var(--accent-rose)' }}>
        Failed to load community intel: {error}
      </div>
      <div style={{ textAlign: 'center' }}>
        <button onClick={load} style={{
          padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
          fontSize: 12, fontWeight: 600, background: 'var(--accent-cyan)', color: '#fff',
        }}>Retry</button>
      </div>
    </div>
  )
  if (!data) return null

  const posts = data.posts || []
  const queries = [
    data.package_name ? `"${data.package_name}" malware` : null,
    data.family && data.family !== 'unknown' ? `"${data.family}" android malware` : null,
  ].filter(Boolean)

  return (
    <div>
      <div className="card" style={{ padding: '12px 16px', marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Searching public forums (Reddit, Hacker News, DuckDuckGo) for mentions of
          {data.package_name ? <strong> {data.package_name}</strong> : ' the package'}
          {data.family && data.family !== 'unknown' && <span> / family <strong>{data.family}</strong></span>}.
          Queries: <span className="text-mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{queries.join(' · ') || 'android malware apk forum'}</span>
        </div>
      </div>

      {posts.length === 0 ? (
        <div className="empty-state">
          <p>No community discussion found for this app or family.</p>
          {data.sources_failed?.length > 0 && (
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
              Sources unreachable: {data.sources_failed.join(', ')}
            </p>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {posts.map((post, i) => {
            const style = SOURCE_STYLES[post.source] || { color: 'var(--text-muted)', bg: 'var(--bg-surface)' }
            return (
              <div key={i} className="card" style={{ padding: '12px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className="badge" style={{ background: style.bg, color: style.color, fontSize: 10 }}>
                    {post.source}
                  </span>
                  {post.subreddit && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>r/{post.subreddit}</span>
                  )}
                  {post.score > 0 && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>▲ {post.score}</span>
                  )}
                  {formatWhen(post.published_at) && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{formatWhen(post.published_at)}</span>
                  )}
                  {post.author && (
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>by {post.author}</span>
                  )}
                </div>
                <a
                  href={post.url}
                  target="_blank"
                  rel="noreferrer"
                  style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-cyan)', textDecoration: 'none' }}
                >
                  {post.title}
                </a>
                {post.snippet && (
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.5 }}>
                    {post.snippet}
                  </p>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

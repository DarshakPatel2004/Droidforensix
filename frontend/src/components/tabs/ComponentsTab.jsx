import { useState, useEffect } from 'react'
import ComponentCard from '../ComponentCard'

const COMPONENT_TYPES = ['activities', 'services', 'receivers', 'providers']
const COMPONENT_LABELS = { activities: 'Activity', services: 'Service', receivers: 'Broadcast Receiver', providers: 'Content Provider' }

export default function ComponentsTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeType, setActiveType] = useState('activities')

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/components`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d.components); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading components...</div>
  if (!data) return <div className="empty-state">No component data available</div>

  const items = data[activeType] || []

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        {COMPONENT_TYPES.map(type => {
          const count = (data[type] || []).length
          return (
            <button key={type} onClick={() => setActiveType(type)} style={{
              padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: 600,
              background: activeType === type ? 'var(--accent-cyan)' : 'var(--bg-surface)',
              color: activeType === type ? '#fff' : 'var(--text-secondary)',
            }}>
              {COMPONENT_LABELS[type]} ({count})
            </button>
          )
        })}
      </div>

      {items.length === 0 ? (
        <div className="empty-state">No {COMPONENT_LABELS[activeType].toLowerCase()} components found</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {items.map((comp, i) => (
            <ComponentCard
              key={i}
              name={comp.name}
              exported={comp.exported}
              intentFilters={comp.intent_filters}
              type={COMPONENT_LABELS[activeType]}
            />
          ))}
        </div>
      )}
    </div>
  )
}

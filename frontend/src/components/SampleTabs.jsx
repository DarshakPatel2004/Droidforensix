// Tab bar for the selected sample. Locked tabs are disabled until analysis completes.
// Arrow keys move between enabled tabs, as the ARIA tab pattern expects.
export default function SampleTabs({ tabs, activeTab, lockedIds = [], onSelect }) {
  const handleKeyDown = (event) => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
    const enabled = tabs.filter((t) => !lockedIds.includes(t.id))
    const current = enabled.findIndex((t) => t.id === activeTab)
    const step = event.key === 'ArrowRight' ? 1 : -1
    const next = enabled[(current + step + enabled.length) % enabled.length]
    if (!next) return
    event.preventDefault()
    onSelect(next.id)
    event.currentTarget.parentElement.querySelector(`[data-tab-id="${next.id}"]`)?.focus()
  }

  return (
    <nav aria-label="Sample sections" role="tablist" className="tab-bar" style={{ overflowX: 'auto' }} onKeyDown={handleKeyDown}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          data-tab-id={tab.id}
          aria-selected={activeTab === tab.id}
          tabIndex={activeTab === tab.id ? 0 : -1}
          className={activeTab === tab.id ? 'selected' : ''}
          disabled={lockedIds.includes(tab.id)}
          onClick={() => onSelect(tab.id)}
          style={{ whiteSpace: 'nowrap' }}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  )
}

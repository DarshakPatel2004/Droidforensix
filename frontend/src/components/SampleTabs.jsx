// Tab bar for the selected sample. Locked tabs are disabled until analysis completes.
export default function SampleTabs({ tabs, activeTab, lockedIds = [], onSelect }) {
  return (
    <nav aria-label="Sample sections" className="tab-bar" style={{ overflowX: 'auto' }}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={activeTab === tab.id}
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

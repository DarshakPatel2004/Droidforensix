import { useState } from 'react'
import ManifestTab from './tabs/ManifestTab'
import PermissionsTab from './tabs/PermissionsTab'
import ComponentsTab from './tabs/ComponentsTab'
import CodeTab from './tabs/CodeTab'
import StringsTab from './tabs/StringsTab'
import DEXTab from './tabs/DEXTab'
import NativeLibsTab from './tabs/NativeLibsTab'

const TABS = [
  { id: 'manifest', label: 'Manifest' },
  { id: 'permissions', label: 'Permissions' },
  { id: 'components', label: 'Components' },
  { id: 'code', label: 'Code' },
  { id: 'strings', label: 'Strings' },
  { id: 'dex', label: 'DEX' },
  { id: 'native', label: 'Native Libs' },
]

export default function DissectionTabs({ sampleId, apiUrl }) {
  const [activeTab, setActiveTab] = useState('manifest')

  return (
    <div className="card animate-fade-in" style={{ overflow: 'hidden' }}>
      <div style={{
        display: 'flex', gap: 0, borderBottom: '1px solid var(--border-color)',
        overflowX: 'auto', background: 'var(--bg-secondary)',
      }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '10px 18px', border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap',
              background: 'transparent',
              color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              transition: 'all 0.15s',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div style={{ padding: 20 }}>
        <div style={{ display: activeTab === 'manifest' ? '' : 'none' }}><ManifestTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'permissions' ? '' : 'none' }}><PermissionsTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'components' ? '' : 'none' }}><ComponentsTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'code' ? '' : 'none' }}><CodeTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'strings' ? '' : 'none' }}><StringsTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'dex' ? '' : 'none' }}><DEXTab sampleId={sampleId} apiUrl={apiUrl} /></div>
        <div style={{ display: activeTab === 'native' ? '' : 'none' }}><NativeLibsTab sampleId={sampleId} apiUrl={apiUrl} /></div>
      </div>
    </div>
  )
}

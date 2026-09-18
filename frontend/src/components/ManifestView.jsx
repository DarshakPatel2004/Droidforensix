import { useState, useEffect } from 'react'
import '../styles/ManifestView.css'

const DANGEROUS_PERMISSIONS = new Set([
  'android.permission.READ_CALENDAR',
  'android.permission.WRITE_CALENDAR',
  'android.permission.CAMERA',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.GET_ACCOUNTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.RECORD_AUDIO',
  'android.permission.READ_PHONE_STATE',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.CALL_PHONE',
  'android.permission.ANSWER_PHONE_CALLS',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.ADD_VOICEMAIL',
  'android.permission.USE_SIP',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION',
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_WAP_PUSH',
  'android.permission.RECEIVE_MMS',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.READ_MEDIA_IMAGES',
  'android.permission.READ_MEDIA_VIDEO',
  'android.permission.READ_MEDIA_AUDIO',
])

function getPermissionName(perm) {
  if (typeof perm === 'string') return perm
  return perm?.name || perm?.permission || JSON.stringify(perm)
}

function isDangerous(perm) {
  const name = getPermissionName(perm)
  if (typeof perm === 'object' && perm !== null) {
    if (perm.protection_level === 'dangerous') return true
    if (perm.is_dangerous === true) return true
    if (String(perm.flags || '').toUpperCase().includes('DANGEROUS')) return true
  }
  return DANGEROUS_PERMISSIONS.has(name)
}

function getComponentName(item) {
  if (typeof item === 'string') return item
  return item?.name || item?.className || JSON.stringify(item)
}

function ComponentList({ title, items }) {
  const list = items || []
  if (list.length === 0) return null

  return (
    <div className="card manifest-components-card">
      <h4>{title} ({list.length})</h4>
      <ul className="manifest-component-list">
        {list.map((item, i) => (
          <li key={i} className="manifest-component-item text-mono">
            {getComponentName(item)}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function ManifestView({ sample, apiUrl }) {
  const [manifest, setManifest] = useState(null)
  const [components, setComponents] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const sampleId = sample?.sampleId || sample?.sha256 || sample?.uploadId
  const baseUrl = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    if (!sampleId) return

    let stale = false
    const controller = new AbortController()

    const fetchManifest = async () => {
      setLoading(true)
      setError(null)
      try {
        const response = await fetch(
          `${baseUrl}/api/sample/${sampleId}/dissection/manifest`,
          { signal: controller.signal }
        )
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (stale) return
        setManifest(data.manifest || {})

        // Fetch components (activities, services, etc.)
        const [compResponse, permResponse] = await Promise.all([
          fetch(`${baseUrl}/api/sample/${sampleId}/dissection/components`, { signal: controller.signal }),
          fetch(`${baseUrl}/api/sample/${sampleId}/dissection/permissions`, { signal: controller.signal }),
        ])
        if (!stale) {
          if (compResponse.ok) {
            const compData = await compResponse.json()
            setComponents(compData.components || {})
          }
          if (permResponse.ok) {
            const permData = await permResponse.json()
            if (permData.permissions) {
              setManifest(prev => ({ ...prev, uses_permissions: permData.permissions }))
            }
          }
        }
      } catch (err) {
        if (stale || err.name === 'AbortError') return
        setError(err.message)
      } finally {
        if (!stale) setLoading(false)
      }
    }

    fetchManifest()
    return () => {
      stale = true
      controller.abort()
    }
  }, [sampleId, baseUrl])

  if (!sampleId) {
    return (
      <div className="manifest-view state-empty">
        <span className="state-icon">📦</span>
        <h3 className="state-title">No sample selected</h3>
        <p className="state-description">Upload and analyze an APK to view its manifest.</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="manifest-view state-loading">
        <div className="manifest-spinner" />
        <p>Loading manifest…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="manifest-view state-error">
        <span className="state-icon">⚠️</span>
        <h3 className="state-title">Failed to load manifest</h3>
        <p className="state-description">{error}</p>
      </div>
    )
  }

  if (!manifest) {
    return (
      <div className="manifest-view state-empty">
        <span className="state-icon">📦</span>
        <h3 className="state-title">No manifest available</h3>
      </div>
    )
  }

  const perms = manifest.uses_permissions || manifest.permissions || []
  const activities = components?.activities || manifest.activities || []
  const services = components?.services || manifest.services || []
  const receivers = components?.receivers || manifest.receivers || []
  const providers = components?.providers || manifest.providers || []

  // Find main activity: first activity with MAIN/LAUNCHER intent filter
  let mainActivity = null
  for (const act of activities) {
    const filters = act.intent_filters
    if (filters && !Array.isArray(filters)) {
      const actions = filters.action || []
      const categories = filters.category || []
      if (actions.includes('android.intent.action.MAIN') || categories.includes('android.intent.category.LAUNCHER')) {
        mainActivity = act.name
        break
      }
    }
  }
  if (!mainActivity && activities.length > 0) {
    mainActivity = activities[0].name
  }

  return (
    <div className="manifest-view tab-panel">
      <div className="card manifest-summary-card">
        <h3>App Details</h3>
        <dl className="manifest-summary-grid">
          <div>
            <dt>Package</dt>
            <dd className="text-mono">{manifest.package || '—'}</dd>
          </div>
          <div>
            <dt>Application Label</dt>
            <dd>{manifest.application?.label || '—'}</dd>
          </div>
          <div>
            <dt>Version Name</dt>
            <dd>{manifest.version_name || '—'}</dd>
          </div>
          <div>
            <dt>Version Code</dt>
            <dd className="text-mono">{manifest.version_code ?? '—'}</dd>
          </div>
          <div>
            <dt>Min SDK</dt>
            <dd className="text-mono">{manifest.min_sdk ?? '—'}</dd>
          </div>
          <div>
            <dt>Target SDK</dt>
            <dd className="text-mono">{manifest.target_sdk ?? '—'}</dd>
          </div>
          <div className="manifest-summary-wide">
            <dt>Main Activity</dt>
            <dd className="text-mono">{mainActivity || '—'}</dd>
          </div>
        </dl>
      </div>

      <div className="card manifest-permissions-card">
        <h3>Permissions ({perms.length})</h3>
        {perms.length === 0 ? (
          <p className="manifest-empty-text">No permissions declared.</p>
        ) : (
          <div className="permissions-cloud">
            {perms.map((perm, i) => {
              const name = getPermissionName(perm)
              return (
                <span
                  key={`${name}-${i}`}
                  className={`permission-badge ${isDangerous(perm) ? 'dangerous' : ''}`}
                  title={name}
                >
                  {name}
                </span>
              )
            })}
          </div>
        )}
      </div>

      <div className="manifest-components-grid">
        <ComponentList title="Activities" items={activities} />
        <ComponentList title="Services" items={services} />
        <ComponentList title="Receivers" items={receivers} />
        <ComponentList title="Providers" items={providers} />
      </div>
    </div>
  )
}

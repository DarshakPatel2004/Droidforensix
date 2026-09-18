import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ManifestView from '../src/components/ManifestView'

const MOCK_MANIFEST = {
  manifest: {
    package: 'com.example.app',
    version_name: '2.0',
    version_code: 3,
    min_sdk: 21,
    target_sdk: 34,
    application: { label: 'MyApp', debuggable: true },
  },
  components: {
    activities: [{ name: 'com.example.MainActivity', intent_filters: { action: ['android.intent.action.MAIN'], category: ['android.intent.category.LAUNCHER'] } }],
    services: [{ name: 'com.example.SyncService' }],
    receivers: [],
    providers: [],
  },
}

const MOCK_PERMS = {
  permissions: [
    'android.permission.INTERNET',
    'android.permission.SEND_SMS',
  ],
}

beforeEach(() => { vi.clearAllMocks() })

describe('ManifestView', () => {
  test('shows no sample state', () => {
    render(<ManifestView sample={null} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('No sample selected')).toBeTruthy()
  })

  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ManifestView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading manifest…')).toBeTruthy()
  })

  test('renders manifest data on success', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST.components) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_PERMS) })

    render(<ManifestView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('com.example.app')).toBeTruthy()
      expect(screen.getByText('2.0')).toBeTruthy()
      expect(screen.getByText('21')).toBeTruthy()
      expect(screen.getByText('MyApp')).toBeTruthy()
    })
  })

  test('shows error state', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    render(<ManifestView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Failed to load manifest/)).toBeTruthy()
    })
  })

  test('shows permission badges', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST.components) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_PERMS) })

    render(<ManifestView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/INTERNET/)).toBeTruthy()
      expect(screen.getByText(/SEND_SMS/)).toBeTruthy()
    })
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ManifestTab from '../src/components/tabs/ManifestTab'

const MOCK_MANIFEST = {
  manifest: {
    package: 'com.example.malware',
    version_name: '1.0',
    version_code: '1',
    min_sdk: '14',
    target_sdk: '33',
    application: { debuggable: true, allowBackup: true },
    features: ['android.hardware.telephony', 'android.hardware.camera'],
    raw_manifest: '<?xml version="1.0"?><manifest></manifest>',
  },
}

beforeEach(() => { vi.clearAllMocks() })

describe('ManifestTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ManifestTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading manifest...')).toBeTruthy()
  })

  test('renders manifest data on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST) })
    render(<ManifestTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('com.example.malware')).toBeTruthy()
      expect(screen.getAllByText(/1.0/).length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows error on failed fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false })
    render(<ManifestTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('Failed to load manifest data')).toBeTruthy())
  })

  test('shows SDK info', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST) })
    render(<ManifestTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText(/min 14 \/ target 33/)).toBeTruthy())
  })

  test('renders raw manifest', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_MANIFEST) })
    render(<ManifestTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('Raw Manifest')).toBeTruthy())
  })
})

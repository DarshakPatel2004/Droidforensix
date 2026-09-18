import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import NativeLibsTab from '../src/components/tabs/NativeLibsTab'

const MOCK_NATIVE = {
  native_libs: [
    'libnative.so',
    { name: 'libdex.so', arch: 'arm64-v8a', size: 50000 },
  ],
}

beforeEach(() => { vi.clearAllMocks() })

describe('NativeLibsTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<NativeLibsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading native libraries...')).toBeTruthy()
  })

  test('renders library list on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_NATIVE) })
    render(<NativeLibsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('libnative.so')).toBeTruthy()
    })
  })

  test('groups libraries by architecture', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_NATIVE) })
    render(<NativeLibsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/arm64-v8a/)).toBeTruthy()
    })
  })

  test('shows empty state when no native libs', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ native_libs: [] }) })
    render(<NativeLibsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('No native libraries found')).toBeTruthy())
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import StringsTab from '../src/components/tabs/StringsTab'

const MOCK_STRINGS = {
  string_literals: [
    'http://evil.com/beacon',
    'SMSApp.apk',
    'android.app.Activity',
    '发现新版本',
    'AES/CBC/PKCS5Padding',
  ],
}

beforeEach(() => { vi.clearAllMocks() })

describe('StringsTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading strings...')).toBeTruthy()
  })

  test('renders strings on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_STRINGS) })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/SMSApp\.apk/)).toBeTruthy()
      expect(screen.getByText(/evil\.com\/beacon/)).toBeTruthy()
    })
  })

  test('categorizes strings by risk', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_STRINGS) })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/CRITICAL/)).toBeTruthy()
      expect(screen.getByText(/SUSPICIOUS/)).toBeTruthy()
    })
  })

  test('filters strings by search', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_STRINGS) })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/evil\.com/)).toBeTruthy() })
    const searchInput = screen.getByPlaceholderText('Search strings...')
    fireEvent.change(searchInput, { target: { value: 'SMSApp' } })
    expect(screen.queryByText(/evil\.com/)).toBeNull()
    expect(screen.getByText(/SMSApp/)).toBeTruthy()
  })

  test('filters by risk level', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_STRINGS) })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/CRITICAL/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/Suspicious/))
    await waitFor(() => {
      expect(screen.queryByText(/SMSApp\.apk/)).toBeNull()
    })
  })

  test('shows empty state when no data', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('No strings data available')).toBeTruthy())
  })

  test('renders copy buttons on strings', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_STRINGS) })
    render(<StringsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      const copyBtns = screen.getAllByText('[copy]')
      expect(copyBtns.length).toBeGreaterThanOrEqual(1)
    })
  })
})

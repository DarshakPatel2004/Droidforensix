import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import DEXTab from '../src/components/tabs/DEXTab'

const MOCK_DEX = {
  dex_stats: {
    dex_count: 1,
    total_classes: 120,
    total_methods: 850,
    total_strings: 320,
    total_bytes: 1024000,
    is_multidex: false,
    entropy: 6.5,
  },
}

beforeEach(() => { vi.clearAllMocks() })

describe('DEXTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<DEXTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading DEX data...')).toBeTruthy()
  })

  test('renders DEX stats on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DEX) })
    render(<DEXTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('1')).toBeTruthy()
      expect(screen.getByText('120')).toBeTruthy()
      expect(screen.getByText('850')).toBeTruthy()
    })
  })

  test('renders entropy section', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DEX) })
    render(<DEXTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('DEX Entropy')).toBeTruthy()
      expect(screen.getByText('6.50')).toBeTruthy()
    })
  })

  test('shows no data state when empty', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ dex_stats: null }) })
    render(<DEXTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('No DEX data available')).toBeTruthy())
  })
})

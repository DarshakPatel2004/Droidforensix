import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import RelatedSamples from '../src/components/RelatedSamples'
import { clearCache } from '../src/utils/fetchWithCache'

const MOCK_ATTRIBUTION = {
  family: 'XHelper',
  confidence: 0.95,
  confidence_breakdown: {},
  supporting_signals: [],
  related_samples: [
    { sample_id: 'a1b2c3d4e5f6', similarity: 0.97 },
    { sample_id: 'f6e5d4c3b2a1', similarity: 0.89 },
    { sample_id: '111122223333', similarity: 0.76 },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()
  clearCache()
})

describe('RelatedSamples', () => {
  test('shows loading state initially', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<RelatedSamples sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading related samples...')).toBeTruthy()
  })

  test('renders related samples list', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })

    render(<RelatedSamples sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('Related Samples')).toBeTruthy()
      expect(screen.getByText(/97.*High/)).toBeTruthy()
      expect(screen.getByText(/89.*Medium/)).toBeTruthy()
      expect(screen.getByText(/76.*Medium/)).toBeTruthy()
    })
  })

  test('returns nothing when no related samples', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        ...MOCK_ATTRIBUTION,
        related_samples: [],
      }),
    })

    const { container } = render(<RelatedSamples sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(container.textContent).toBe('')
    })
  })

  test('calls onSelect when a sample is clicked', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })
    const onSelect = vi.fn()

    render(<RelatedSamples sampleId="test-001" apiUrl="http://localhost:8000" onSelect={onSelect} />)

    await waitFor(() => {
      expect(screen.getByText('97% · High')).toBeTruthy()
    })

    fireEvent.click(screen.getByText('97% · High').closest('div'))
    expect(onSelect).toHaveBeenCalledWith('a1b2c3d4e5f6')
  })

  test('shows error state returns null silently', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    })

    const { container } = render(<RelatedSamples sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(container.textContent).toBe('')
    })
  })
})

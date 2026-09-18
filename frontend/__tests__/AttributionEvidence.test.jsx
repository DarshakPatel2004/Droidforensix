import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AttributionEvidence from '../src/components/AttributionEvidence'
import { clearCache } from '../src/utils/fetchWithCache'

const MOCK_ATTRIBUTION = {
  family: 'XHelper',
  confidence: 0.95,
  confidence_breakdown: {
    permissions_match: 0.92,
    c2_overlap: 0.98,
    obfuscation_pattern: 0.93,
    code_similarity: 0.94,
  },
  supporting_signals: [
    '92% permissions match family baseline',
    'C2 indicators overlap with 3 known indicators',
    'Obfuscation pattern: HIGH',
    'Code structure consistent with XHelper',
  ],
  related_samples: [
    { sample_id: 'abc123', similarity: 0.97 },
    { sample_id: 'def456', similarity: 0.89 },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()
  clearCache()
})

describe('AttributionEvidence', () => {
  test('shows loading state initially', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading attribution evidence...')).toBeTruthy()
  })

  test('renders family and confidence on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })

    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('95% confidence')).toBeTruthy()
      expect(screen.getAllByText('XHelper').length).toBeGreaterThanOrEqual(1)
    })
  })

  test('renders all four confidence dimensions', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })

    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('Permissions Match')).toBeTruthy()
      expect(screen.getByText('C2 Overlap')).toBeTruthy()
      expect(screen.getByText('Obfuscation Pattern')).toBeTruthy()
      expect(screen.getByText('Code Similarity')).toBeTruthy()
    })
  })

  test('renders supporting signals', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })

    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/92%.*permissions/)).toBeTruthy()
    })
  })

  test('renders related samples', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_ATTRIBUTION),
    })

    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/97% similar/)).toBeTruthy()
    })
  })

  test('shows error on failed fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    })

    render(<AttributionEvidence sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/Failed to load/)).toBeTruthy()
    })
  })
})

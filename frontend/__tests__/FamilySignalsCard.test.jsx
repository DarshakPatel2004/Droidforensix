import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import FamilySignalsCard from '../src/components/FamilySignalsCard'
import { clearCache } from '../src/utils/fetchWithCache'

const MOCK_ATTRIBUTION = {
  family: 'Geinimi',
  confidence: 0.9,
  confidence_breakdown: {
    permissions_match: 0.5,
    c2_overlap: 0.5,
    obfuscation_pattern: 0.47,
    code_similarity: 0.0,
  },
  related_samples: [
    { sample_id: 'abc', similarity: 0.95 },
    { sample_id: 'def', similarity: 0.82 },
  ],
}

const MOCK_THREAT_INTEL = {
  family: {
    family: 'Geinimi',
    confidence: 0.9,
    method: 'llm',
    reasoning: 'Strong indicator match across multiple dimensions.',
    candidates: [
      { family: 'Geinimi', confidence: 0.9, source: 'yara', reasoning: 'Duplicate' },
      { family: 'OtherFamily', confidence: 0.6, source: 'signature' },
    ],
  },
}

const MOCK_THREAT_INTEL_NO_CANDIDATES = {
  family: {
    family: 'Geinimi',
    confidence: 0.9,
    method: 'llm',
    reasoning: 'Strong indicator match across multiple dimensions.',
    candidates: [],
  },
}

const MOCK_EMPTY = {
  family: { family: 'unknown', confidence: 0, method: 'none' },
}

beforeEach(() => {
  vi.clearAllMocks()
  clearCache()
})

function renderCard(attributionMock, threatIntelMock) {
  global.fetch = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(attributionMock) })
    .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(threatIntelMock) })

  return render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)
}

describe('FamilySignalsCard', () => {
  test('renders nothing while loading', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    const { container } = render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(container.innerHTML).toBe('')
  })

  test('renders nothing when sampleId is missing', () => {
    const { container } = render(<FamilySignalsCard sampleId="" apiUrl="http://localhost:8000" />)
    expect(container.innerHTML).toBe('')
  })

  test('renders collapsed preview with primary family name', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => {
      expect(screen.getByText('Geinimi')).toBeTruthy()
    })
  })

  test('expands to show breakdown on click', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => {
      expect(screen.getByText('Geinimi')).toBeTruthy()
    })

    fireEvent.click(screen.getByText('Family Signals'))
    await waitFor(() => {
      expect(screen.getByText('Signal Confidence')).toBeTruthy()
      expect(screen.getByText('Permissions Match')).toBeTruthy()
      expect(screen.getByText('C2 Overlap')).toBeTruthy()
      expect(screen.getByText('Obfuscation Pattern')).toBeTruthy()
      expect(screen.getByText('Code Similarity')).toBeTruthy()
    })
  })

  test('collapses on second click', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())

    fireEvent.click(screen.getByText('Family Signals'))
    await waitFor(() => expect(screen.getByText('Signal Confidence')).toBeTruthy())

    fireEvent.click(screen.getByText('Family Signals'))
    await waitFor(() => {
      expect(screen.queryByText('Signal Confidence')).toBeNull()
    })
  })

  test('shows method badge with LLM label', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.getByText('LLM')).toBeTruthy()
    })
  })

  test('shows family reasoning text', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.getByText('Strong indicator match across multiple dimensions.')).toBeTruthy()
    })
  })

  test('hides card for unknown family with no signals', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_EMPTY) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_EMPTY) })

    const { container } = render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(container.innerHTML).toBe('')
    })
  })

  test('renders with attribution data only (threat-intel fails)', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ATTRIBUTION) })
      .mockRejectedValueOnce(new Error('Not found'))

    render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('Geinimi')).toBeTruthy()
    })
  })

  test('renders with threat-intel data only (attribution fails)', async () => {
    global.fetch = vi.fn()
      .mockRejectedValueOnce(new Error('Not found'))
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_THREAT_INTEL) })

    render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('Geinimi')).toBeTruthy()
    })
  })

  test('filters duplicate family names from candidates', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.getByText('Alternative Candidates')).toBeTruthy()
    })

    expect(screen.getAllByText('OtherFamily').length).toBeGreaterThanOrEqual(1)
  })

  test('shows no candidates section when empty after dedup', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ATTRIBUTION) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_THREAT_INTEL_NO_CANDIDATES) })

    render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.queryByText('Alternative Candidates')).toBeNull()
    })
  })

  test('shows related samples count', async () => {
    renderCard(MOCK_ATTRIBUTION, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.getByText(/2 known samples with this family/)).toBeTruthy()
    })
  })

  test('hides related samples when attribution has none', async () => {
    const noRelated = { ...MOCK_ATTRIBUTION, related_samples: [] }
    renderCard(noRelated, MOCK_THREAT_INTEL)

    await waitFor(() => expect(screen.getByText('Geinimi')).toBeTruthy())
    fireEvent.click(screen.getByText('Family Signals'))

    await waitFor(() => {
      expect(screen.queryByText(/known samples/)).toBeNull()
    })
  })

  test('both endpoints fail silently shows nothing', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

    const { container } = render(<FamilySignalsCard sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(container.innerHTML).toBe('')
    })
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import OverviewTab from '../src/components/tabs/OverviewTab'

vi.mock('../src/hooks/useSampleData', () => ({
  useSampleData: vi.fn(),
}))

import { useSampleData } from '../src/hooks/useSampleData'

const RESULT = {
  llm_assessment: { risk_score: 72, severity: 'medium' },
  obfuscation_analysis: { obfuscation_score: 16, obfuscation_level: 'low' },
  threat_synthesis: { zero_day_risk_score: 0, risk_level: 'none' },
  family_identification: { family: 'KungFu', confidence: 0.9 },
  threat_chains: [{ severity: 'medium' }],
  binary_packing: { packing_detected: false },
}

function mockData({ result = RESULT, summary = { c2_count: 8 }, attribution = { family: 'KungFu', confidence: 0.95 }, resultError = null } = {}) {
  useSampleData.mockImplementation((id, endpoint) => {
    if (endpoint.endsWith('/threat-summary')) return { data: summary, error: null }
    if (endpoint.endsWith('/attribution')) return { data: attribution, error: null }
    return { data: resultError ? null : result, error: resultError }
  })
}

beforeEach(() => vi.clearAllMocks())

describe('OverviewTab', () => {
  test('shows a loading state before the result arrives', () => {
    useSampleData.mockReturnValue({ data: null, error: null })
    render(<OverviewTab sampleId="abc" />)
    expect(screen.getByText('Loading overview...')).toBeTruthy()
  })

  test('shows the four key figures', () => {
    mockData()
    render(<OverviewTab sampleId="abc" />)
    expect(screen.getByText('LLM risk')).toBeTruthy()
    expect(screen.getByText('C2 indicators')).toBeTruthy()
    expect(screen.getByText('Obfuscation')).toBeTruthy()
    expect(screen.getAllByText('Zero-day risk').length).toBeGreaterThanOrEqual(1)
  })

  test('states the family match with its confidence', () => {
    mockData()
    render(<OverviewTab sampleId="abc" />)
    expect(screen.getByText(/Matched to KungFu \(95% confidence\)/)).toBeTruthy()
  })

  test('lists what needs attention', async () => {
    mockData()
    render(<OverviewTab sampleId="abc" />)
    await waitFor(() => expect(screen.getByText('8 unique C2 indicators found')).toBeTruthy())
    expect(screen.getByText('1 threat chain at medium severity or higher')).toBeTruthy()
  })

  test('shows an error when the sample cannot be loaded', () => {
    mockData({ resultError: new Error('HTTP 404') })
    render(<OverviewTab sampleId="abc" />)
    expect(screen.getByRole('alert').textContent).toContain('HTTP 404')
  })

  test('renders the nine deep-analysis checks', () => {
    mockData()
    render(<OverviewTab sampleId="abc" />)
    expect(screen.getByRole('heading', { name: 'Deep analysis' })).toBeTruthy()
    expect(screen.getAllByRole('article')).toHaveLength(9)
  })
})

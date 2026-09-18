import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ThreatSummary from '../src/components/ThreatSummary'

const MOCK_SUMMARY = {
  sample_id: 'test-001',
  package_name: 'com.evil.malware',
  version_name: '1.0',
  threat_score: 85,
  threat_level: 'CRITICAL',
  severity: 'critical',
  red_flags: [
    { type: 'dangerous_permissions', count: 7 },
    { type: 'active_c2_endpoints', count: 3 },
    { type: 'obfuscation', level: 'HIGH' },
    { type: 'evasion_techniques', count: 5 },
  ],
  family: 'XHelper',
  confidence: 0.95,
  similar_samples_count: 47,
  c2_count: 3,
  obfuscation_score: 72,
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ThreatSummary', () => {
  test('shows loading state initially', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ThreatSummary sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading threat summary...')).toBeTruthy()
  })

  test('renders threat data on successful fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_SUMMARY),
    })

    render(<ThreatSummary sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('com.evil.malware')).toBeTruthy()
      expect(screen.getByText('CRITICAL (85/100)')).toBeTruthy()
      expect(screen.getByText('XHelper')).toBeTruthy()
      expect(screen.getByText('95% confidence')).toBeTruthy()
    })
  })

  test('shows red flags from API data', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_SUMMARY),
    })

    render(<ThreatSummary sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('dangerous permissions')).toBeTruthy()
      expect(screen.getByText('active c2 endpoints')).toBeTruthy()
      expect(screen.getByText('obfuscation')).toBeTruthy()
      expect(screen.getByText('evasion techniques')).toBeTruthy()
    })
  })

  test('shows error state on failed fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    })

    render(<ThreatSummary sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/Failed to load/)).toBeTruthy()
    })
  })

  test('renders version name when present', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_SUMMARY),
    })

    render(<ThreatSummary sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/v1\.0/)).toBeTruthy()
    })
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import ThreatIntelView from '../src/components/ThreatIntelView'

vi.mock('react-leaflet', () => ({
  MapContainer: ({ children }) => <div data-testid="map-container">{children}</div>,
  TileLayer: () => <div data-testid="tile-layer" />,
  Marker: ({ children }) => <div data-testid="marker">{children}</div>,
  Popup: ({ children }) => <div data-testid="popup">{children}</div>,
  useMap: () => ({ fitBounds: vi.fn() }),
}))

const MOCK_DATA = {
  dns: { active: 2, likely_active: 1, dead: 0 },
  classification: { malicious: 2, suspicious: 1, benign: 0 },
  c2s: [
    { c2_id: 'c2-1', domain: 'evil.com', protocol: 'https', port: 443, status: 'active', classification: 'malicious' },
    { c2_id: 'c2-2', ip: '192.168.1.1', status: 'likely_active', classification: 'suspicious' },
    { c2_id: 'c2-3', domain: 'benign.net', status: 'dead', classification: 'benign' },
  ],
  ips_geolocated: [
    { ip: '192.168.1.1', country: 'US', region: 'California', latitude: 34.05, longitude: -118.25, ip_type: 'public' },
  ],
  family: { family: 'XHelper', confidence: 0.95, method: 'llm' },
}

beforeEach(() => { vi.clearAllMocks() })

describe('ThreatIntelView', () => {
  test('shows no sample state', () => {
    render(<ThreatIntelView sample={null} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/No sample selected/)).toBeTruthy()
  })

  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/Loading Threat Intelligence/)).toBeTruthy()
  })

  test('renders threat intelligence dashboard', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Threat Intelligence Dashboard/)).toBeTruthy()
      expect(screen.getAllByText(/3/).length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows C2 indicators table', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('evil.com')).toBeTruthy()
      expect(screen.getAllByText(/C2/).length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows malware family card', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('XHelper')).toBeTruthy()
    })
  })

  test('shows DNS stats', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getAllByText('Active').length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText('Likely Active').length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows geographic distribution section', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Geographic Distribution/)).toBeTruthy()
      expect(screen.getAllByText('192.168.1.1').length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows export PDF section', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Export Report/)).toBeTruthy()
    })
  })

  test('shows error state when data unavailable', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('fetch failed'))
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Phase 2 enrichment/)).toBeTruthy()
    })
  })

  test('shows classification bars', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_DATA) })
    render(<ThreatIntelView sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getAllByText(/Malicious/).length).toBeGreaterThanOrEqual(1)
    })
  })
})

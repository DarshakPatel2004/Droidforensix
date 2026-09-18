import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import App from '../src/App'

const wsOnOpenRef = { current: null }

vi.mock('../src/hooks/useSampleData', () => ({
  useSampleData: () => ({ data: null, loading: true, error: null }),
}))

vi.mock('../src/components/UploadPanel', () => ({
  default: () => <div data-testid="upload-panel">UploadPanel</div>,
}))

vi.mock('../src/components/SampleSearch', () => ({
  default: () => <div>SampleSearch</div>,
}))

vi.mock('../src/components/ErrorBoundary', () => ({
  ErrorBoundary: ({ children }) => <div data-testid="error-boundary">{children}</div>,
}))

vi.mock('../src/components/LoadingSpinner', () => ({
  default: ({ message }) => <div data-testid="loading-spinner">{message}</div>,
}))

vi.mock('../src/components/ThreatBadge', () => ({
  default: () => <span>ThreatBadge</span>,
}))

vi.mock('../src/components/AnalysisView', () => ({
  default: () => <div>AnalysisView</div>,
}))

vi.mock('../src/components/DissectionPage', () => ({
  default: () => <div>DissectionPage</div>,
}))

vi.mock('../src/components/RawCodeView', () => ({
  default: () => <div>RawCodeView</div>,
}))

vi.mock('../src/pages/SampleDetail', () => ({
  default: () => <div>SampleDetail</div>,
}))

vi.mock('../src/components/ThreatIntelView', () => ({
  default: () => <div>ThreatIntelView</div>,
}))

function renderApp(initialRoute = '/') {
  return render(
    <MemoryRouter initialEntries={[initialRoute]}>
      <App />
    </MemoryRouter>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
  // Mock WebSocket
  global.WebSocket = vi.fn(() => {
    const ws = {
      send: vi.fn(),
      close: vi.fn(),
      readyState: 1,
      addEventListener: vi.fn(),
      set onopen(fn) { wsOnOpenRef.current = fn },
      get onopen() { return wsOnOpenRef.current },
    }
    return ws
  })
})

describe('App', () => {
  test('renders sidebar with navigation items', () => {
    renderApp()
    expect(screen.getAllByText(/UPLOAD/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/ANALYSIS/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/DISSECTION/i).length).toBeGreaterThanOrEqual(1)
  })

  test('sidebar nav items are disabled without selected sample', () => {
    renderApp()
    const analysisBtn = screen.getByText('Analysis Results').closest('button')
    expect(analysisBtn?.disabled).toBe(true)
  })

  test('upload tab shows UploadPanel', () => {
    renderApp()
    expect(screen.getByTestId('upload-panel')).toBeTruthy()
  })

  test('renders brand name', () => {
    renderApp()
    expect(screen.getByText('DROID')).toBeTruthy()
    expect(screen.getByText('FORENSIX')).toBeTruthy()
  })

  test('shows Help and Documentation link', () => {
    renderApp()
    expect(screen.getByText(/Documentation/)).toBeTruthy()
  })

  test('shows status indicator', () => {
    renderApp()
    expect(screen.getByRole('status')).toBeTruthy()
  })
})

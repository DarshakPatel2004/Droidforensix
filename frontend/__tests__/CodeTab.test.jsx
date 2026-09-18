import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import CodeTab from '../src/components/tabs/CodeTab'

const MOCK_CLASSES = {
  classes: [
    { name: 'com.example.MainActivity', method_count: 5 },
    { name: 'com.example.CryptoHelper', method_count: 3 },
  ],
}

const MOCK_ANALYSIS = {
  class_name: 'com.example.MainActivity',
  attack_flow: [
    { step: 1, method: 'onCreate', risk_level: 'CRITICAL', description: 'Entry point', line: 12 },
    { step: 2, method: 'decryptPayload', risk_level: 'HIGH', description: 'Decrypts embedded payload', line: 45 },
  ],
  methods: [
    {
      name: 'onCreate',
      risk_level: 'CRITICAL',
      start_line: 10,
      end_line: 30,
      techniques: ['reflection', 'crypto_usage'],
      suspicious_lines: [
        { line: 15, code: 'Class.forName("android.telephony.TelephonyManager")', pattern: 'reflection' },
      ],
      calls: [{ target: 'decryptPayload' }],
    },
    {
      name: 'decryptPayload',
      risk_level: 'HIGH',
      start_line: 40,
      end_line: 60,
      techniques: ['crypto_usage'],
      suspicious_lines: [],
      calls: [],
    },
  ],
  string_references: {
    'http://evil.com/beacon': ['onCreate L12', 'decryptPayload L42'],
  },
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText: vi.fn().mockResolvedValue() } })
})

describe('CodeTab', () => {
  test('shows empty state when no class selected', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_CLASSES),
    })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText('Select a class to view code analysis')).toBeTruthy()
    })
  })

  test('renders class list with method counts', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_CLASSES),
    })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/MainActivity/)).toBeTruthy()
      expect(screen.getByText(/CryptoHelper/)).toBeTruthy()
      expect(screen.getByText(/5m/)).toBeTruthy()
      expect(screen.getByText(/3m/)).toBeTruthy()
    })
  })

  test('loads analysis when class selected', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })
    global.fetch = fetchMock

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/MainActivity/)).toBeTruthy()
    })

    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText('com.example.MainActivity')).toBeTruthy()
    })

    const onCreateElements = screen.getAllByText(/onCreate/)
    expect(onCreateElements.length).toBeGreaterThanOrEqual(1)
    const decryptElements = screen.getAllByText(/decryptPayload/)
    expect(decryptElements.length).toBeGreaterThanOrEqual(1)
  })

  test('renders attack flow section and step descriptions', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/Entry point/)).toBeTruthy()
      expect(screen.getByText(/Decrypts embedded payload/)).toBeTruthy()
    })
  })

  test('renders suspicious lines with hover annotation', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/suspicious line/)).toBeTruthy()
    })

    const suspiciousLine = screen.getByText(/Class\.forName/)
    expect(suspiciousLine).toBeTruthy()
    fireEvent.mouseEnter(suspiciousLine)

    await waitFor(() => {
      expect(screen.getByText(/Reflection abuse/)).toBeTruthy()
    })
  })

  test('renders technique badges with hover popup', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/reflection/)).toBeTruthy()
    })

    const cryptoBadges = screen.getAllByText(/crypto usage/)
    expect(cryptoBadges.length).toBeGreaterThanOrEqual(1)

    fireEvent.mouseEnter(screen.getByText(/reflection/))

    await waitFor(() => {
      expect(screen.getByText(/dynamically accesses restricted/)).toBeTruthy()
    })
  })

  test('shows copy buttons for analysis content', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText('copy analysis')).toBeTruthy()
      expect(screen.getByText('copy all')).toBeTruthy()
    })

    const copyButtons = screen.getAllByText('copy')
    expect(copyButtons.length).toBeGreaterThanOrEqual(2)
  })

  test('switches between Attack Flow and Raw Source views', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText('copy analysis')).toBeTruthy()
    })

    fireEvent.click(screen.getByText('Raw Source'))

    await waitFor(() => {
      expect(screen.getByText('copy source')).toBeTruthy()
    })
  })

  test('filters class list by search', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_CLASSES),
    })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => {
      expect(screen.getByText(/MainActivity/)).toBeTruthy()
    })

    const searchInput = screen.getByPlaceholderText('Search classes...')
    fireEvent.change(searchInput, { target: { value: 'Crypto' } })

    expect(screen.queryByText(/MainActivity/)).toBeNull()
    expect(screen.getByText(/CryptoHelper/)).toBeTruthy()
  })

  test('renders string references section', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/String References \(\d+\)/)).toBeTruthy()
      expect(screen.getByText(/http:\/\/evil\.com\/beacon/)).toBeTruthy()
    })
  })

  test('copies analysis JSON on "copy analysis" click', async () => {
    const writeText = vi.fn().mockResolvedValue()
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })

    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      const copyAnalysis = screen.getByText('copy analysis')
      expect(copyAnalysis).toBeTruthy()
      fireEvent.click(copyAnalysis)
      expect(writeText).toHaveBeenCalled()
    })
  })

  test('shows method line ranges', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/L10–30/)).toBeTruthy()
      expect(screen.getByText(/L40–60/)).toBeTruthy()
    })
  })

  test('switches to flow diagram view', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText('List View')).toBeTruthy()
      expect(screen.getByText('Flow Diagram')).toBeTruthy()
    })

    fireEvent.click(screen.getByText('Flow Diagram'))

    await waitFor(() => {
      expect(screen.getByText('Attack Flow Diagram')).toBeTruthy()
    })
  })

  test('toggles between list and diagram flow views', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => { expect(screen.getByText('List View')).toBeTruthy() })

    fireEvent.click(screen.getByText('Flow Diagram'))
    await waitFor(() => { expect(screen.getByText('Attack Flow Diagram')).toBeTruthy() })

    fireEvent.click(screen.getByText('List View'))
    await waitFor(() => { expect(screen.getByText('Attack Flow (list)')).toBeTruthy() })
  })

  test('renders share and export buttons when analysis loaded', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText('share')).toBeTruthy()
      expect(screen.getByText('export')).toBeTruthy()
      expect(screen.getByText('copy analysis')).toBeTruthy()
    })
  })

  test('mark button toggles on method', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      const onCreateElements = screen.getAllByText(/onCreate/)
      expect(onCreateElements.length).toBeGreaterThanOrEqual(1)
    })

    const flagButtons = screen.getAllByText('flag')
    expect(flagButtons.length).toBeGreaterThanOrEqual(1)

    fireEvent.click(flagButtons[0])

    const flaggedButtons = screen.getAllByText(/✓ flagged/)
    expect(flaggedButtons.length).toBeGreaterThanOrEqual(1)

    fireEvent.click(flaggedButtons[0])

    const flagButtonsAfter = screen.getAllByText('flag')
    expect(flagButtonsAfter.length).toBeGreaterThanOrEqual(1)
  })

  test('string reference has find-in-source button', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/http:\/\/evil\.com\/beacon/)).toBeTruthy()
    })

    const searchButtons = screen.getAllByText('🔍')
    expect(searchButtons.length).toBeGreaterThanOrEqual(1)
  })

  test('clicking string reference navigates to source view', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => {
      expect(screen.getByText(/http:\/\/evil\.com\/beacon/)).toBeTruthy()
    })

    const beaconEl = screen.getByText(/http:\/\/evil\.com\/beacon/)
    fireEvent.click(beaconEl)

    await waitFor(() => {
      expect(screen.getByText(/Raw Source/)).toBeTruthy()
    })
  })

  test('suspicious line has mark and view-in-source buttons', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_ANALYSIS) })

    render(<CodeTab sampleId="test-001" apiUrl="http://localhost:8000" />)

    await waitFor(() => { expect(screen.getByText(/MainActivity/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/MainActivity/))

    await waitFor(() => { expect(screen.getByText(/suspicious line/)).toBeTruthy() })

    const searchInSource = screen.getAllByText('🔍')
    expect(searchInSource.length).toBeGreaterThanOrEqual(1)

    const markAll = screen.getByText('mark all')
    expect(markAll).toBeTruthy()
  })
})

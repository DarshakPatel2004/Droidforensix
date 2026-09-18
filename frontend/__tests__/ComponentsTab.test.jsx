import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import ComponentsTab from '../src/components/tabs/ComponentsTab'

const MOCK_COMPONENTS = {
  components: {
    activities: [{ name: 'com.example.MainActivity', exported: true, intent_filters: ['android.intent.action.MAIN'] }],
    services: [{ name: 'com.example.HiddenService', exported: false }],
    receivers: [],
    providers: [],
  },
}

beforeEach(() => { vi.clearAllMocks() })

describe('ComponentsTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ComponentsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading components...')).toBeTruthy()
  })

  test('renders components on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_COMPONENTS) })
    render(<ComponentsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('com.example.MainActivity')).toBeTruthy()
    })
  })

  test('switches between component types', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_COMPONENTS) })
    render(<ComponentsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText('Activity (1)')).toBeTruthy() })
    fireEvent.click(screen.getByText(/Service/))
    await waitFor(() => {
      expect(screen.getByText('com.example.HiddenService')).toBeTruthy()
    })
  })

  test('shows empty state when no components of a type', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_COMPONENTS) })
    render(<ComponentsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText('Activity (1)')).toBeTruthy() })
    fireEvent.click(screen.getByText(/Broadcast Receiver/))
    await waitFor(() => expect(screen.getByText(/No broadcast receiver components found/)).toBeTruthy())
  })
})

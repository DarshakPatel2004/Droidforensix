import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import RawCodeView from '../src/components/RawCodeView'

const MOCK_CLASSES = {
  classes: [
    { name: 'com.example.MainActivity', method_count: 5 },
    { name: 'com.example.Helper', method_count: 2 },
  ],
}

beforeEach(() => { vi.clearAllMocks() })

describe('RawCodeView', () => {
  test('shows no sample state without sample', () => {
    render(<RawCodeView sample={null} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('No sample selected.')).toBeTruthy()
  })

  test('renders class list on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
    render(<RawCodeView sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('MainActivity')).toBeTruthy()
      expect(screen.getByText('Helper')).toBeTruthy()
    })
  })

  test('shows class count', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
    render(<RawCodeView sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/2 of 2 classes/)).toBeTruthy()
    })
  })

  test('shows empty state when no class selected', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
    render(<RawCodeView sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('Select a class to view its decompiled source code')).toBeTruthy()
    })
  })
})

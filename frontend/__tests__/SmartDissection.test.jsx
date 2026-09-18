import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SmartDissection from '../src/components/SmartDissection'

const MOCK_CLASSES = {
  classes: [
    { name: 'com.example.LegitClass', method_names: ['toString', 'onCreate'], method_count: 2 },
    { name: 'com.example.CryptoHelper', method_names: ['encrypt', 'decrypt', 'initCipher'], method_count: 3 },
  ],
}

const MOCK_METHODS = {
  methods: [
    { name: 'encrypt', body: 'Cipher cipher = Cipher.getInstance("AES");' },
    { name: 'decrypt', body: 'return cipher.doFinal(data);' },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('SmartDissection', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/Loading Code Dissection/)).toBeTruthy()
  })

  test('renders classes on success', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/CryptoHelper/)).toBeTruthy()
      expect(screen.getByText(/LegitClass/)).toBeTruthy()
    })
  })

  test('shows filter buttons', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getAllByText(/All Classes/).length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText(/Suspicious/).length).toBeGreaterThanOrEqual(1)
    })
  })

  test('filters to suspicious classes', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/CryptoHelper/)).toBeTruthy() })
    fireEvent.click(screen.getAllByText(/Suspicious/)[0])
    expect(screen.queryByText(/LegitClass/)).toBeNull()
    expect(screen.getByText(/CryptoHelper/)).toBeTruthy()
  })

  test('searches classes by name', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/CryptoHelper/)).toBeTruthy() })
    const searchInput = screen.getByPlaceholderText(/Search class/)
    fireEvent.change(searchInput, { target: { value: 'Legit' } })
    expect(screen.getByText(/LegitClass/)).toBeTruthy()
    expect(screen.queryByText(/CryptoHelper/)).toBeNull()
  })

  test('exposes View source button when onSelectClass is provided', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    const onSelect = vi.fn()
    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" onSelectClass={onSelect} />)
    await waitFor(() => {
      const buttons = screen.getAllByText('View source')
      expect(buttons.length).toBeGreaterThanOrEqual(1)
    })
  })

  test('shows error state with retry', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network failure'))
    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Failed to load dissection/)).toBeTruthy()
    })
    expect(screen.getByText('Retry')).toBeTruthy()
  })

  test('shows empty state when no results match filter', async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_CLASSES) })
      .mockResolvedValueOnce({ ok: false })

    render(<SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/CryptoHelper/)).toBeTruthy() })
    const searchInput = screen.getByPlaceholderText(/Search class/)
    fireEvent.change(searchInput, { target: { value: 'zzz_nonexistent' } })
    expect(screen.getByText(/No matching classes/)).toBeTruthy()
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import NotesTab from '../src/components/tabs/NotesTab'

vi.mock('../src/api/client', () => ({
  apiFetch: vi.fn(),
}))

import { apiFetch } from '../src/api/client'

const STATE = { sample_id: 'abc', status: 'new', tags: ['c2', 'kungfu'], notes: 'first look', updated_utc: null }

beforeEach(() => vi.clearAllMocks())

describe('NotesTab', () => {
  test('loads and shows the saved state', async () => {
    apiFetch.mockResolvedValue(STATE)
    render(<NotesTab sampleId="abc" />)
    await waitFor(() => expect(screen.getByDisplayValue('first look')).toBeTruthy())
    expect(screen.getByDisplayValue('c2, kungfu')).toBeTruthy()
    expect(apiFetch).toHaveBeenCalledWith('/api/sample/abc/analyst-state')
  })

  test('saves status, tags and notes with PUT', async () => {
    apiFetch.mockResolvedValueOnce(STATE).mockResolvedValueOnce({ ...STATE, status: 'closed' })
    render(<NotesTab sampleId="abc" />)
    await waitFor(() => screen.getByDisplayValue('first look'))

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'closed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save notes' }))

    await waitFor(() => expect(screen.getByText('Saved')).toBeTruthy())
    const [, options] = apiFetch.mock.calls[1]
    expect(options.method).toBe('PUT')
    expect(JSON.parse(options.body)).toEqual({ status: 'closed', tags: ['c2', 'kungfu'], notes: 'first look' })
  })

  test('shows the server error when the save is refused', async () => {
    apiFetch.mockResolvedValueOnce(STATE).mockRejectedValueOnce(new Error('HTTP 422'))
    render(<NotesTab sampleId="abc" />)
    await waitFor(() => screen.getByDisplayValue('first look'))
    fireEvent.click(screen.getByRole('button', { name: 'Save notes' }))
    await waitFor(() => expect(screen.getByText('Not saved: HTTP 422')).toBeTruthy())
  })

  test('shows an error when the state cannot be loaded', async () => {
    apiFetch.mockRejectedValue(new Error('HTTP 404'))
    render(<NotesTab sampleId="abc" />)
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('HTTP 404'))
  })
})

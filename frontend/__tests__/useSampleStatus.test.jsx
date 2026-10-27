import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useSampleStatus } from '../src/hooks/useSampleStatus'

vi.mock('../src/api/client', async () => {
  const actual = await vi.importActual('../src/api/client')
  return { ...actual, apiFetch: vi.fn() }
})

import { apiFetch } from '../src/api/client'

beforeEach(() => vi.clearAllMocks())
afterEach(() => vi.useRealTimers())

describe('useSampleStatus', () => {
  test('returns null status and no polling without an id', () => {
    const { result } = renderHook(() => useSampleStatus(null))
    expect(result.current.status).toBeNull()
    expect(apiFetch).not.toHaveBeenCalled()
  })

  test('reports completed and stops polling', async () => {
    apiFetch.mockResolvedValue({ status: 'completed', error: null })
    const { result } = renderHook(() => useSampleStatus('abc'))
    await waitFor(() => expect(result.current.status).toBe('completed'))
    expect(apiFetch).toHaveBeenCalledTimes(1)
    expect(apiFetch).toHaveBeenCalledWith('/api/sample/abc/status')
  })

  test('keeps polling while analysing, then stops at completed', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    apiFetch
      .mockResolvedValueOnce({ status: 'analyzing', error: null })
      .mockResolvedValueOnce({ status: 'completed', error: null })
    const { result } = renderHook(() => useSampleStatus('abc'))
    await waitFor(() => expect(result.current.status).toBe('analyzing'))
    await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
    await waitFor(() => expect(result.current.status).toBe('completed'))
    expect(apiFetch).toHaveBeenCalledTimes(2)
  })

  test('does not retry after a 404', async () => {
    const { ApiError } = await vi.importActual('../src/api/client')
    apiFetch.mockRejectedValue(new ApiError(404, 'Sample not found'))
    const { result } = renderHook(() => useSampleStatus('missing'))
    await waitFor(() => expect(result.current.error).toBe('Sample not found'))
    expect(apiFetch).toHaveBeenCalledTimes(1)
  })
})

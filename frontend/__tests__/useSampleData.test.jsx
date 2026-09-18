import { describe, test, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useSampleData } from '../src/hooks/useSampleData'

vi.mock('../src/api/client', () => ({
  apiFetch: vi.fn(),
  apiFetchCached: vi.fn((url) => {
    if (url.includes('fail')) return Promise.reject(new Error('HTTP 500'))
    return Promise.resolve({ id: 'abc', name: 'test' })
  }),
}))

import { apiFetch, apiFetchCached } from '../src/api/client'

beforeEach(() => vi.clearAllMocks())

describe('useSampleData', () => {
  test('returns loading initially', () => {
    const { result } = renderHook(() => useSampleData('abc', '/api/sample/abc'))
    expect(result.current.loading).toBe(true)
    expect(result.current.data).toBeNull()
    expect(result.current.error).toBeNull()
  })

  test('returns data on success', async () => {
    const { result } = renderHook(() => useSampleData('abc', '/api/sample/abc'))
    await waitFor(() => {
      expect(result.current.loading).toBe(false)
      expect(result.current.data).toEqual({ id: 'abc', name: 'test' })
    })
  })

  test('returns error on failure', async () => {
    const { result } = renderHook(() => useSampleData('abc', '/fail'))
    await waitFor(() => {
      expect(result.current.loading).toBe(false)
      expect(result.current.error).toBeTruthy()
    })
  })

  test('does not fetch when immediate is false', () => {
    renderHook(() => useSampleData('abc', '/api/sample/abc', { immediate: false }))
    expect(apiFetchCached).not.toHaveBeenCalled()
  })

  test('does not fetch without sampleId', () => {
    renderHook(() => useSampleData(null, '/api/sample/abc'))
    expect(apiFetchCached).not.toHaveBeenCalled()
  })
})

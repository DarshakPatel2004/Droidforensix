import { describe, test, expect, vi, beforeEach } from 'vitest'
import { apiFetch, apiFetchCached, clearApiCache, ApiError } from '../src/api/client'

beforeEach(() => {
  vi.restoreAllMocks()
  clearApiCache()
})

describe('apiFetch', () => {
  test('sends JSON headers', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ data: 'ok' }) })
    await apiFetch('/test')
    expect(fetch).toHaveBeenCalledWith('http://localhost:8000/test', {
      headers: { 'Content-Type': 'application/json' },
    })
  })

  test('throws ApiError on non-ok response', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404, json: () => Promise.resolve({ detail: 'Not found' }) })
    await expect(apiFetch('/missing')).rejects.toThrow(ApiError)
  })

  test('throws ApiError with text body fallback', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500, json: () => Promise.reject(), text: () => Promise.resolve('Server error') })
    await expect(apiFetch('/error')).rejects.toThrow('Server error')
  })

  test('returns parsed JSON on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ key: 'value' }) })
    const result = await apiFetch('/success')
    expect(result).toEqual({ key: 'value' })
  })
})

describe('apiFetchCached', () => {
  test('caches results', async () => {
    const fn = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ data: 'cached' }) })
    global.fetch = fn
    const r1 = await apiFetchCached('/cache-test')
    const r2 = await apiFetchCached('/cache-test')
    expect(r1).toEqual({ data: 'cached' })
    expect(r2).toEqual({ data: 'cached' })
    expect(fn).toHaveBeenCalledTimes(1)
  })

  test('cache key includes options', async () => {
    const fn = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
    global.fetch = fn
    await apiFetchCached('/a', { method: 'POST' })
    await apiFetchCached('/a', { method: 'GET' })
    expect(fn).toHaveBeenCalledTimes(2)
  })
})

describe('clearApiCache', () => {
  test('clears cached results', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
    await apiFetchCached('/clear-test')
    clearApiCache()
    await apiFetchCached('/clear-test')
    expect(fetch).toHaveBeenCalledTimes(2)
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { fetchWithCache, clearCache } from '../src/utils/fetchWithCache'

beforeEach(() => {
  vi.restoreAllMocks()
  clearCache()
})

describe('fetchWithCache', () => {
  test('fetches and caches results', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ data: 'hello' }) })
    const r1 = await fetchWithCache('/test')
    const r2 = await fetchWithCache('/test')
    expect(r1).toEqual({ data: 'hello' })
    expect(r2).toEqual({ data: 'hello' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  test('throws on non-ok response', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 })
    await expect(fetchWithCache('/fail')).rejects.toThrow('HTTP 404')
  })

  test('cache key includes options', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
    await fetchWithCache('/a', { method: 'POST' })
    await fetchWithCache('/a', { method: 'GET' })
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  test('clearCache removes entries', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) })
    await fetchWithCache('/clear-me')
    clearCache()
    await fetchWithCache('/clear-me')
    expect(fetch).toHaveBeenCalledTimes(2)
  })
})

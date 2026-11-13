const cache = new Map()

export class ApiError extends Error {
  constructor(status, body) {
    super(typeof body === 'string' ? body : body?.detail || `HTTP ${status}`)
    this.status = status
    this.body = body
  }
}

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function buildUrl(path) {
  if (path.startsWith('http://') || path.startsWith('https://')) return path
  const base = BASE.replace(/\/+$/, '')
  const clean = path.replace(/^\/+/, '')
  return `${base}/${clean}`
}

export async function apiFetch(path, options = {}) {
  const url = buildUrl(path)
  const res = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  })
  if (!res.ok) {
    let body
    try { body = await res.json() } catch { body = await res.text().catch(() => null) }
    throw new ApiError(res.status, body)
  }
  return res.json()
}

export function apiFetchCached(path, options) {
  const key = path + (options ? JSON.stringify(options) : '')
  if (!cache.has(key)) {
    const pending = apiFetch(path, options)
    // Evict failures so a transient error or a 404 before analysis finishes is not served for the session.
    pending.catch(() => {
      if (cache.get(key) === pending) cache.delete(key)
    })
    cache.set(key, pending)
  }
  return cache.get(key)
}

export function clearApiCache() {
  cache.clear()
}

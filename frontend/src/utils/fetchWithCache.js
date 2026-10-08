const cache = new Map()

export function fetchWithCache(url, options) {
  const key = url + (options ? JSON.stringify(options) : '')
  if (!cache.has(key)) {
    const pending = fetch(url, options).then(async (res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      return data
    })
    // Evict on failure: a rejected promise kept in the Map is served to every
    // later caller for the session's lifetime, so a transient 500 or a backend
    // restart permanently breaks that panel with no way to recover short of a
    // full page reload.
    pending.catch(() => {
      if (cache.get(key) === pending) cache.delete(key)
    })
    cache.set(key, pending)
  }
  return cache.get(key)
}

export function clearCache() {
  cache.clear()
}

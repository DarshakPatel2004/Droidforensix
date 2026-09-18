const cache = new Map()

export function fetchWithCache(url, options) {
  const key = url + (options ? JSON.stringify(options) : '')
  if (!cache.has(key)) {
    cache.set(key, fetch(url, options).then(async (res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      return data
    }))
  }
  return cache.get(key)
}

export function clearCache() {
  cache.clear()
}

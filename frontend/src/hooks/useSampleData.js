import { useState, useEffect } from 'react'
import { apiFetch, apiFetchCached } from '../api/client'
/* eslint-disable react-hooks/set-state-in-effect */

export function useSampleData(sampleId, endpoint, options = {}) {
  const { cached = true, immediate = true } = options
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchFn = cached ? apiFetchCached : apiFetch

  useEffect(() => {
    if (!sampleId || !endpoint || !immediate) return
    let cancelled = false
    setLoading(true)
    setError(null)
    fetchFn(endpoint)
      .then(d => { if (!cancelled) setData(d) })
      .catch(e => { if (!cancelled) setError(e) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [sampleId, endpoint, cached, immediate, fetchFn])

  return { data, loading, error }
}

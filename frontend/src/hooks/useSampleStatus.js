import { useState, useEffect } from 'react'
import { apiFetch, ApiError } from '../api/client'
/* eslint-disable react-hooks/set-state-in-effect */

const POLL_INTERVAL_MS = 2000
const FINISHED_STATUSES = new Set(['completed', 'failed'])

// Polls GET /api/sample/{id}/status until the analysis has finished.
// Retries only on network errors; a 404 (unknown id) is final.
export function useSampleStatus(sampleId) {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setStatus(null)
    setError(null)
    if (!sampleId) return undefined

    let cancelled = false
    let timer = null

    const poll = async () => {
      try {
        const body = await apiFetch(`/api/sample/${encodeURIComponent(sampleId)}/status`)
        if (cancelled) return
        setStatus(body.status)
        setError(body.error || null)
        if (!FINISHED_STATUSES.has(body.status)) {
          timer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      } catch (e) {
        if (cancelled) return
        setError(e.message)
        if (!(e instanceof ApiError)) {
          timer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      }
    }

    poll()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [sampleId])

  return { status, error }
}

import { useState, useEffect } from 'react'
import { apiFetch, ApiError } from '../api/client'
/* eslint-disable react-hooks/set-state-in-effect */

const POLL_INTERVAL_MS = 2000
const FINISHED_STATUSES = new Set(['completed', 'failed'])

// Polls GET /api/sample/{id}/status until the analysis has finished.
// Retries only on network errors. A 404 switches to fallbackId (the sha256) once,
// because upload ids are lost on backend restart while the stored result survives.
export function useSampleStatus(sampleId, fallbackId) {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  // Verdict is present once the status is completed; the header reads it for samples opened by URL.
  const [verdict, setVerdict] = useState(null)

  useEffect(() => {
    setStatus(null)
    setError(null)
    setVerdict(null)
    if (!sampleId) return undefined

    let cancelled = false
    let timer = null
    let activeId = sampleId

    const poll = async () => {
      try {
        const body = await apiFetch(`/api/sample/${encodeURIComponent(activeId)}/status`)
        if (cancelled) return
        setStatus(body.status)
        setError(body.error || null)
        if (body.severity !== undefined) setVerdict({ severity: body.severity, risk_score: body.risk_score })
        if (!FINISHED_STATUSES.has(body.status)) {
          timer = setTimeout(poll, POLL_INTERVAL_MS)
        }
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 404 && fallbackId && activeId !== fallbackId) {
          activeId = fallbackId
          poll()
          return
        }
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
  }, [sampleId, fallbackId])

  return { status, error, verdict }
}

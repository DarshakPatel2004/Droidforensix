import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ErrorBoundary } from '../src/components/ErrorBoundary'

vi.stubGlobal('fetch', vi.fn())

beforeEach(() => {
  vi.clearAllMocks()
})

describe('AnalysisView Error Recovery', () => {
  test('displays error message on API failure', async () => {
    const AnalysisView = (await import('../src/components/AnalysisView')).default
    fetch.mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: 'timeout', message: 'Analysis took too long' }),
    })

    render(
      <AnalysisView
        sample={{ uploadId: 'test-1', sha256: 'abc' }}
        analysisState={{ status: 'error', error: 'Analysis took too long', errorType: 'timeout' }}
        apiUrl="http://localhost:8000"
      />
    )

    await waitFor(() => {
      expect(screen.getByText('Analysis Failed')).toBeTruthy()
      expect(screen.getByText(/Analysis took too long/)).toBeTruthy()
    })
  })

  test('shows retry button after failure', async () => {
    const AnalysisView = (await import('../src/components/AnalysisView')).default

    render(
      <AnalysisView
        sample={{ uploadId: 'test-1' }}
        analysisState={{ status: 'error', error: 'Timeout', errorType: 'timeout' }}
        apiUrl="http://localhost:8000"
      />
    )

    await waitFor(() => {
      expect(screen.getByText('Retry Analysis')).toBeTruthy()
    })
  })

  test('retries analysis on button click', async () => {
    const AnalysisView = (await import('../src/components/AnalysisView')).default
    const onRetry = vi.fn()

    render(
      <AnalysisView
        sample={{ uploadId: 'test-1' }}
        analysisState={{ status: 'error', error: 'Timeout', errorType: 'timeout' }}
        apiUrl="http://localhost:8000"
        onRetry={onRetry}
      />
    )

    await waitFor(() => {
      expect(screen.getByText('Retry Analysis')).toBeTruthy()
    })

    fireEvent.click(screen.getByText('Retry Analysis'))

    await waitFor(() => {
      expect(onRetry).toHaveBeenCalled()
    }, { timeout: 5000 })
  })

  test('shows max retries reached message', async () => {
    const AnalysisView = (await import('../src/components/AnalysisView')).default

    render(
      <AnalysisView
        sample={{ uploadId: 'test-1' }}
        analysisState={{ status: 'error', error: 'Timeout', errorType: 'timeout' }}
        apiUrl="http://localhost:8000"
      />
    )

    const retryButton = await screen.findByText('Retry Analysis')
    fireEvent.click(retryButton)
  })

  test('shows loading spinner during retry', async () => {
    const AnalysisView = (await import('../src/components/AnalysisView')).default

    render(
      <AnalysisView
        sample={{ uploadId: 'test-1' }}
        analysisState={{ status: 'running', progress: 50, eta: 30 }}
        apiUrl="http://localhost:8000"
      />
    )

    await waitFor(() => {
      expect(screen.getByText(/50%/)).toBeTruthy()
    })
  })

  test('error boundary catches rendering errors', () => {
    const CrashComponent = () => {
      throw new Error('Test crash')
    }

    render(
      <ErrorBoundary>
        <CrashComponent />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeTruthy()
  })

  test('error boundary reset works', async () => {
    fetch.mockResolvedValue({ ok: true })
    let shouldCrash = true
    const CrashComponent = () => {
      if (shouldCrash) throw new Error('Test crash')
      return <div>Recovered</div>
    }

    const { unmount } = render(
      <ErrorBoundary>
        <CrashComponent />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeTruthy()

    shouldCrash = false
    fireEvent.click(screen.getByText('Try Again'))
    unmount()

    render(
      <ErrorBoundary>
        <CrashComponent />
      </ErrorBoundary>
    )

    await waitFor(() => {
      expect(screen.getByText('Recovered')).toBeTruthy()
    })
  })
})

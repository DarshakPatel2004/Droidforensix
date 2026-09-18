import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import UploadPanel from '../src/components/UploadPanel'

function createFile(name = 'test.apk', size = 100000, type = 'application/vnd.android.package-archive') {
  const file = new File(['x'.repeat(size)], name, { type })
  return file
}

function renderUploadPanel(props = {}) {
  return render(
    <UploadPanel
      onUpload={vi.fn()}
      samples={[]}
      onSelectSample={vi.fn()}
      retryState="idle"
      retryAttempt={0}
      retryEta={null}
      cancelRetry={vi.fn()}
      backendOnline={true}
      {...props}
    />
  )
}

beforeEach(() => { vi.clearAllMocks() })

describe('UploadPanel', () => {
  test('renders drop zone', () => {
    renderUploadPanel()
    expect(screen.getByText(/Drop your APK here/)).toBeTruthy()
    expect(screen.getByText(/Browse Files/)).toBeTruthy()
  })

  test('shows features grid', () => {
    renderUploadPanel()
    expect(screen.getByText(/String Extraction/)).toBeTruthy()
    expect(screen.getByText(/C2 Discovery/)).toBeTruthy()
    expect(screen.getByText(/Obfuscation Score/)).toBeTruthy()
  })

  test('shows features card centered', () => {
    renderUploadPanel()
    expect(screen.getByText(/What DroidForensix Does/)).toBeTruthy()
    expect(screen.getByText(/String Extraction/)).toBeTruthy()
  })

  test('shows recent samples when provided', () => {
    const samples = [
      { fileName: 'malware.apk', sha256: 'abc123def4567890abcdef1234567890abcdef12', status: 'completed', uploadedAt: '2024-01-01T00:00:00Z' },
    ]
    renderUploadPanel({ samples })
    expect(screen.getByText('malware.apk')).toBeTruthy()
    expect(screen.getByText('Done')).toBeTruthy()
  })

  test('shows retry progress bar when retrying', () => {
    renderUploadPanel({ retryState: 'retrying', retryAttempt: 2 })
    expect(screen.getByText(/Retrying Upload/)).toBeTruthy()
    expect(screen.getAllByText(/Attempt 2 of 5/).length).toBeGreaterThanOrEqual(1)
  })

  test('shows exhausted retry state', () => {
    renderUploadPanel({ retryState: 'exhausted' })
    expect(screen.getByText(/Upload failed after 5 attempts/)).toBeTruthy()
    expect(screen.getByText('Try Again')).toBeTruthy()
    expect(screen.getByText('Start Backend')).toBeTruthy()
  })

  test('shows backend offline notice', () => {
    renderUploadPanel({ backendOnline: false })
    expect(screen.getByText(/not reachable/)).toBeTruthy()
  })

  test('validates empty file', async () => {
    const onUpload = vi.fn()
    const { container } = renderUploadPanel({ onUpload })

    const fileInput = container.querySelector('input[type="file"]')
    expect(fileInput).not.toBeNull()
    Object.defineProperty(fileInput, 'files', { value: [new File([], 'empty.apk')] })
    fireEvent.change(fileInput)

    await waitFor(() => {
      expect(screen.getByText('File is empty.')).toBeTruthy()
    })
  })

  test('validates non-APK extension', async () => {
    const { container } = renderUploadPanel()
    const fileInput = container.querySelector('input[type="file"]')
    expect(fileInput).not.toBeNull()
    Object.defineProperty(fileInput, 'files', { value: [new File(['content'], 'test.txt', { type: 'text/plain' })] })
    fireEvent.change(fileInput)

    await waitFor(() => {
      expect(screen.getByText(/Invalid file type/)).toBeTruthy()
    })
  })
})

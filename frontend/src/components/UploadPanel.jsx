import { useState, useCallback, useRef } from 'react'
import '../styles/UploadPanel.css'

// One drawn icon set, one stroke weight. Replaces emoji glyphs.
const ICON_PATHS = {
  upload: 'M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3',
  alert: 'M12 9v4m0 4h.01M10.3 3.9 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  error: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-6h.01M12 8v4',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-8v4m0-8h.01',
  file: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6',
}

function Icon({ name, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={ICON_PATHS[name]} />
    </svg>
  )
}


const MAX_SIZE_MB = 100

/**
 * Client-side file validation (Phase 2).
 * Returns null on success, or an error string on failure.
 */
function validateFile(file) {
  // Non-empty check
  if (!file || file.size === 0) {
    return 'File is empty.'
  }

  // Extension check
  if (!file.name.toLowerCase().endsWith('.apk')) {
    return `Invalid file type. Only .apk files are supported. Your file is .${file.name.split('.').pop() || 'unknown'}.`
  }

  // Size check
  const sizeMB = file.size / (1024 * 1024)
  if (sizeMB > MAX_SIZE_MB) {
    return `File is too large (${sizeMB.toFixed(1)}MB). Maximum allowed size is ${MAX_SIZE_MB}MB.`
  }

  return null // valid
}

/**
 * Validate APK magic bytes by reading the first 4 bytes.
 * APK files are ZIP archives and must start with PK\x03\x04.
 */
function validateMagicBytes(file) {
  return new Promise((resolve) => {
    const slice = file.slice(0, 4)
    const reader = new FileReader()
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result)
      const valid = bytes[0] === 0x50 && // P
                    bytes[1] === 0x4B && // K
                    bytes[2] === 0x03 &&
                    bytes[3] === 0x04
      if (!valid) {
        resolve('File is not a valid APK (bad header — expected ZIP signature).')
      } else {
        resolve(null)
      }
    }
    reader.onerror = () => resolve(null) // Can't read header, let server validate
    reader.readAsArrayBuffer(slice)
  })
}

export default function UploadPanel({
  onUpload,
  samples,
  onSelectSample,
  retryState,
  retryAttempt,
  retryEta,
  cancelRetry,
  backendOnline,
}) {
  const [dragActive, setDragActive] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [inlineError, setInlineError] = useState(null)
  const [showBackendInstructions, setShowBackendInstructions] = useState(false)
  const fileInputRef = useRef(null)

  const processFile = useCallback(async (file) => {
    setInlineError(null)

    // Synchronous validation (extension, size, MIME)
    const syncError = validateFile(file)
    if (syncError) {
      setInlineError(syncError)
      return
    }

    // Async validation (magic bytes)
    const headerError = await validateMagicBytes(file)
    if (headerError) {
      setInlineError(headerError)
      return
    }

    setUploading(true)
    setUploadProgress(0)

    const progressInterval = setInterval(() => {
      setUploadProgress(p => Math.min(p + Math.random() * 15, 90))
    }, 250)

    try {
      await onUpload(file)
      setUploadProgress(100)
    } finally {
      clearInterval(progressInterval)
      setTimeout(() => {
        setUploading(false)
        setUploadProgress(0)
      }, 400)
    }
  }, [onUpload])

  const handleDrag = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const isRetrying = retryState === 'retrying'
  const isExhausted = retryState === 'exhausted'
  const maxRetries = 5
  const showBackendOffline = !backendOnline && !isRetrying && !isExhausted

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (uploading || isRetrying) return
    const files = e.dataTransfer.files
    if (files && files[0]) {
      processFile(files[0])
    }
  }, [processFile, uploading, isRetrying])

  const handleChange = useCallback((e) => {
    if (uploading || isRetrying) return
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0])
    }
    // Reset input so same file can be re-selected
    e.target.value = ''
  }, [processFile, uploading, isRetrying])

  return (
    <div className="upload-panel">
      <section className="upload-hero card">
        <div
          className={`upload-dropzone ${dragActive ? 'active' : ''} ${uploading || isRetrying ? 'uploading' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <div className="upload-dropzone-content">
            <div className="upload-illustration"><Icon name="upload" size={26} /></div>
            <h2>{uploading ? 'Uploading APK...' : isRetrying ? 'Retrying Upload...' : 'Drop your APK here'}</h2>
            <p className="upload-subtitle">
              {uploading
                ? 'Scanning file signature and beginning static analysis'
                : isRetrying
                  ? `Attempt ${retryAttempt} of ${maxRetries}`
                  : 'or click below to browse your device'}
            </p>

            {!uploading && !isRetrying && (
              <label
                className="upload-primary-button"
                role="button"
                tabIndex={0}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    fileInputRef.current?.click()
                  }
                }}
              >
                Browse Files
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".apk"
                  onChange={handleChange}
                  disabled={uploading || isRetrying}
                  style={{ display: 'none' }}
                />
              </label>
            )}

            {uploading && (
              <div className="upload-progress">
                <div className="upload-progress-track">
                  <div className="upload-progress-bar" style={{ width: `${uploadProgress}%` }}></div>
                </div>
                <span className="upload-progress-text">{Math.round(uploadProgress)}%</span>
              </div>
            )}

            <p className="upload-hint">APK files only &bull; Max {MAX_SIZE_MB}MB</p>
          </div>
        </div>

        {/* Inline error display (Phase 1) */}
        {inlineError && (
          <div className="upload-inline-error">
            <span className="upload-inline-error-icon"><Icon name="error" /></span>
            <span className="upload-inline-error-text">{inlineError}</span>
            <button
              className="upload-inline-error-dismiss"
              onClick={() => setInlineError(null)}
              aria-label="Dismiss error"
            >
              ×
            </button>
          </div>
        )}

        {/* Retry progress bar (Phase 4) */}
        {isRetrying && (
          <div className="upload-retry-bar">
            <div className="retry-info">
              <span className="retry-icon"><Icon name="alert" /></span>
              <span className="retry-text">
                Attempt {retryAttempt} of {maxRetries}
                {retryEta != null && retryEta > 0 && (
                  <> &bull; Retrying in {retryEta}s...</>
                )}
              </span>
            </div>
            <div className="retry-progress-track">
              <div
                className="retry-progress-bar"
                style={{ width: `${(retryAttempt / maxRetries) * 100}%` }}
              ></div>
            </div>
            <button className="retry-cancel-btn" onClick={cancelRetry}>
              Cancel
            </button>
          </div>
        )}

        {/* Exhausted retries — show Try Again + Start Backend (Phase 4, 5) */}
        {isExhausted && (
          <div className="upload-exhausted">
            <div className="exhausted-icon"><Icon name="error" size={22} /></div>
            <p className="exhausted-title">Upload failed after {maxRetries} attempts</p>
            <p className="exhausted-hint">The backend at localhost:8000 may not be running.</p>
            <div className="exhausted-actions">
              <button
                className="upload-primary-button retry-again-btn"
                onClick={() => {
                  // Re-trigger last file
                  if (fileInputRef.current) fileInputRef.current.click()
                }}
              >
                Try Again
              </button>
              <button
                className="start-backend-btn"
                onClick={() => setShowBackendInstructions(prev => !prev)}
              >
                Start Backend
              </button>
            </div>
          </div>
        )}

        {/* Backend start instructions (Phase 5) */}
        {/* Proactive backend offline notice (Phase 5) */}
        {showBackendOffline && (
          <div className="upload-offline-notice">
            <span className="offline-icon"><Icon name="alert" /></span>
            <span className="offline-text">
              Backend at localhost:8000 is not reachable.
            </span>
            <button
              className="start-backend-btn"
              onClick={() => setShowBackendInstructions(prev => !prev)}
            >
              Start Backend
            </button>
          </div>
        )}

        {showBackendInstructions && (
          <div className="backend-instructions">
            <div className="backend-instructions-header">
              <span className="instructions-icon"><Icon name="info" /></span>
              <span>Backend is not running. Start it with:</span>
            </div>
            <div className="backend-instructions-code">
              <code>python -m uvicorn backend.main:app --port 8000</code>
              <button
                className="copy-btn"
                onClick={() => {
                  const cmd = 'python -m uvicorn backend.main:app --port 8000'
                  try {
                    navigator.clipboard.writeText(cmd)
                  } catch {
                    // Fallback for HTTP contexts or older browsers
                    const ta = document.createElement('textarea')
                    ta.value = cmd
                    ta.style.position = 'fixed'
                    ta.style.opacity = '0'
                    document.body.appendChild(ta)
                    ta.select()
                    document.execCommand('copy')
                    document.body.removeChild(ta)
                  }
                }}
              >
                Copy
              </button>
            </div>
            <p className="backend-instructions-note">
              Or run <code>run_backend.bat</code> from the project root.
            </p>
            <p className="backend-instructions-note">
              The page will automatically detect when the backend comes online.
            </p>
            <button
              className="backend-instructions-dismiss"
              onClick={() => setShowBackendInstructions(false)}
            >
              Dismiss
            </button>
          </div>
        )}
      </section>

      <section className="upload-grid">
        {samples.length > 0 && (
          <div className="recent-samples card">
            <div className="card-header">
              <h3>Recent Samples</h3>
              <span className="sample-count">{samples.length}</span>
            </div>
            <div className="samples-list">
              {samples.map((sample, idx) => (
                <div key={idx} className="sample-row">
                  <div className="sample-row-icon"><Icon name="file" /></div>
                  <div className="sample-row-info">
                    <p className="sample-row-name" title={sample.fileName}>{sample.fileName}</p>
                    <p className="sample-row-hash">{sample.sha256.substring(0, 24)}...</p>
                    {sample.uploadedAt && (
                      <p className="sample-row-time">{new Date(sample.uploadedAt).toLocaleString()}</p>
                    )}
                  </div>
                  <div className="sample-row-actions">
                    <span className={`status-pill ${sample.status}`}>
                      {sample.status === 'uploaded' && 'Queued'}
                      {sample.status === 'analyzing' && 'Analyzing'}
                      {sample.status === 'completed' && 'Done'}
                      {sample.status === 'analyzed' && 'Analyzed'}
                      {sample.status === 'failed' && 'Failed'}
                    </span>
                    <button
                      className="view-sample-btn"
                      onClick={() => onSelectSample(sample)}
                      disabled={sample.status === 'analyzing'}
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </section>
    </div>
  )
}

import { createContext, useCallback, useContext, useState, useRef, useEffect } from 'react'
import '../styles/Toast.css'

const ToastContext = createContext(null)

let toastIdCounter = 0

/**
 * Lightweight toast notification system.
 * Categories: success, info, warning, error
 * Auto-dismiss: success=3s, info=5s, warning=8s, error=manual
 */
function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const timersRef = useRef({})

  const removeToast = useCallback((id) => {
    clearTimeout(timersRef.current[id])
    delete timersRef.current[id]
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const addToast = useCallback((message, type = 'info', opts = {}) => {
    const id = ++toastIdCounter
    const toast = { id, message, type, ...opts }
    setToasts(prev => [...prev, toast])

    // Auto-dismiss durations by type
    const durations = { success: 3000, info: 5000, warning: 8000 }
    const duration = opts.duration ?? durations[type]
    if (duration) {
      timersRef.current[id] = setTimeout(() => removeToast(id), duration)
    }

    return id
  }, [removeToast])

  // Cleanup all timers on unmount
  useEffect(() => {
    const ref = timersRef
    return () => {
      Object.values(ref.current).forEach(clearTimeout)
    }
  }, [])

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <div className="toast-container" role="alert" aria-live="polite">
        {toasts.map(toast => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            <span className="toast-icon">
              {toast.type === 'success' && '✅'}
              {toast.type === 'info' && 'ℹ️'}
              {toast.type === 'warning' && '⚠️'}
              {toast.type === 'error' && '❌'}
            </span>
            <span className="toast-message">{toast.message}</span>
            <button
              className="toast-dismiss"
              onClick={() => removeToast(toast.id)}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}

// eslint-disable-next-line react-refresh/only-export-components
export { ToastProvider, useToast }

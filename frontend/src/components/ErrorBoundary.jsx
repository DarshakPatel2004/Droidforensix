import { Component } from 'react'

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo })
    if (import.meta.env.DEV) {
      console.error('ErrorBoundary caught:', error, errorInfo)
    }
    fetch('http://localhost:8000/api/log-error', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: error?.toString(),
        stack: errorInfo?.componentStack,
        timestamp: new Date().toISOString(),
      }),
    }).catch(() => {})
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '24px', margin: '20px',
          border: '1px solid #f5222d', borderRadius: '6px',
          backgroundColor: '#fff2f0',
        }}>
          <h2 style={{ color: '#f5222d', margin: '0 0 8px', fontSize: '18px' }}>
            Something went wrong
          </h2>
          <p style={{ margin: '0 0 16px', color: '#666', lineHeight: 1.5 }}>
            An unexpected error occurred. Please try again or contact support.
          </p>
          <button
            onClick={this.handleReset}
            style={{
              padding: '8px 20px', backgroundColor: '#1890ff', color: '#fff',
              border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '14px',
            }}
          >
            Try Again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

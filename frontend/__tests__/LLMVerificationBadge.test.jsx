import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import LLMVerificationBadge from '../src/components/LLMVerificationBadge'

describe('LLMVerificationBadge', () => {
  test('returns null for null input', () => {
    const { container } = render(<LLMVerificationBadge llmResult={null} />)
    expect(container.innerHTML).toBe('')
  })

  test('shows disabled message when status is disabled', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'disabled' }} />)
    expect(screen.getByText(/LLM Verification Disabled/)).toBeTruthy()
  })

  test('shows error message on error status', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'error', error: 'ollama timeout' }} />)
    expect(screen.getByText(/LLM Verification Failed/)).toBeTruthy()
    expect(screen.getByText(/ollama timeout/)).toBeTruthy()
  })

  test('renders malicious verdict', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'success', is_malicious: true, confidence: 'high', false_positive_likelihood: 'low', latency_seconds: 2.5 }} />)
    expect(screen.getByText(/MALICIOUS/)).toBeTruthy()
    expect(screen.getByText('high')).toBeTruthy()
    expect(screen.getByText('low')).toBeTruthy()
    expect(screen.getByText('2.5s')).toBeTruthy()
  })

  test('renders benign verdict', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'success', is_malicious: false, confidence: 'medium' }} />)
    expect(screen.getByText(/BENIGN/)).toBeTruthy()
  })

  test('shows reasoning text when present', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'success', is_malicious: true, reasoning: 'Suspicious reflection pattern detected' }} />)
    expect(screen.getByText(/Suspicious reflection pattern detected/)).toBeTruthy()
  })

  test('shows verbose details when verbose prop is true', () => {
    render(<LLMVerificationBadge llmResult={{ status: 'success', is_malicious: true }} verbose />)
    expect(screen.getByText('Show Details')).toBeTruthy()
  })
})

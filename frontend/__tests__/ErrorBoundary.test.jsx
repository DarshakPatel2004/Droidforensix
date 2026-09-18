import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ErrorBoundary } from '../src/components/ErrorBoundary'

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  global.fetch = vi.fn().mockResolvedValue({ ok: true })
})

describe('ErrorBoundary', () => {
  test('renders children when no error', () => {
    render(<ErrorBoundary><div>child content</div></ErrorBoundary>)
    expect(screen.getByText('child content')).toBeTruthy()
  })

  test('renders error UI on caught error', () => {
    const Throw = () => { throw new Error('test error') }
    render(<ErrorBoundary><Throw /></ErrorBoundary>)
    expect(screen.getByText('Something went wrong')).toBeTruthy()
    expect(screen.getByText('Try Again')).toBeTruthy()
  })

  test('reset button re-renders children (if they throw again, error persists)', () => {
    const Throw = () => { throw new Error('test error') }
    render(<ErrorBoundary><Throw /></ErrorBoundary>)
    expect(screen.getByText('Something went wrong')).toBeTruthy()
    fireEvent.click(screen.getByText('Try Again'))
    expect(screen.getByText('Something went wrong')).toBeTruthy()
  })
})

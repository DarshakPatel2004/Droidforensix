import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import LoadingSpinner from '../src/components/LoadingSpinner'

describe('LoadingSpinner', () => {
  test('renders with message', () => {
    render(<LoadingSpinner message="Loading data..." />)
    expect(screen.getByText('Loading data...')).toBeTruthy()
  })

  test('renders without message', () => {
    const { container } = render(<LoadingSpinner />)
    expect(container.querySelector('div')).toBeTruthy()
  })
})

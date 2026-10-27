import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import SampleNotReady from '../src/components/SampleNotReady'

describe('SampleNotReady', () => {
  test('shows the queued message', () => {
    render(<SampleNotReady status="queued" />)
    expect(screen.getByText('Queued for analysis.')).toBeTruthy()
  })

  test('shows the analysing message', () => {
    render(<SampleNotReady status="analyzing" />)
    expect(screen.getByText(/Analysing/)).toBeTruthy()
  })

  test('shows a checking message before the first status arrives', () => {
    render(<SampleNotReady status={null} />)
    expect(screen.getByText('Checking analysis status…')).toBeTruthy()
  })

  test('shows the error when analysis failed', () => {
    render(<SampleNotReady status="failed" error="Step 8 timed out" />)
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.getByText('Step 8 timed out')).toBeTruthy()
  })
})

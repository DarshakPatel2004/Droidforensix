import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import ConfidenceBar from '../src/components/ConfidenceBar'

describe('ConfidenceBar', () => {
  test('renders with value 0', () => {
    render(<ConfidenceBar value={0} label="Test" />)
    expect(screen.getByText('Test')).toBeTruthy()
    expect(screen.getByText('0%')).toBeTruthy()
  })

  test('renders with value 1.0', () => {
    render(<ConfidenceBar value={1.0} label="Full" />)
    expect(screen.getByText('Full')).toBeTruthy()
    expect(screen.getByText('100%')).toBeTruthy()
  })

  test('renders with value 0.5', () => {
    render(<ConfidenceBar value={0.5} label="Half" />)
    expect(screen.getByText('Half')).toBeTruthy()
    expect(screen.getByText('50%')).toBeTruthy()
  })

  test('clamps values above 1.0', () => {
    render(<ConfidenceBar value={1.5} label="Over" />)
    expect(screen.getByText('100%')).toBeTruthy()
  })

  test('clamps values below 0', () => {
    render(<ConfidenceBar value={-0.5} label="Under" />)
    expect(screen.getByText('0%')).toBeTruthy()
  })

  test('renders without label when showLabel is false', () => {
    render(<ConfidenceBar value={0.5} label="Hidden" showLabel={false} />)
    expect(screen.queryByText('Hidden')).toBeNull()
  })

  test('renders with custom color', () => {
    render(<ConfidenceBar value={0.5} label="Custom" color="#ff0000" />)
    expect(screen.getByText('Custom')).toBeTruthy()
    expect(screen.getByText('50%')).toBeTruthy()
  })

  test('renders with sm size', () => {
    const { container } = render(<ConfidenceBar value={0.5} size="sm" />)
    expect(container.querySelector('[style*="height: 6px"]')).toBeTruthy()
  })
})

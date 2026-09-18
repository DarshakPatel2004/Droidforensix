import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import ThreatBadge from '../src/components/ThreatBadge'

describe('ThreatBadge', () => {
  test('renders CRITICAL with correct label', () => {
    render(<ThreatBadge level="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeTruthy()
  })

  test('renders custom label when provided', () => {
    render(<ThreatBadge level="CRITICAL" label="MALICIOUS" />)
    expect(screen.getByText('MALICIOUS')).toBeTruthy()
  })

  test('renders LOW level', () => {
    render(<ThreatBadge level="LOW" />)
    expect(screen.getByText('LOW')).toBeTruthy()
  })

  test('renders UNKNOWN for missing level', () => {
    render(<ThreatBadge />)
    expect(screen.getByText('UNKNOWN')).toBeTruthy()
  })
})

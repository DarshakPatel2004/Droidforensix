import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import MITREDisplay from '../src/components/MITREDisplay'

describe('MITREDisplay', () => {
  test('returns null for empty tactics', () => {
    const { container } = render(<MITREDisplay tactics={[]} />)
    expect(container.innerHTML).toBe('')
  })

  test('returns null for null tactics', () => {
    const { container } = render(<MITREDisplay tactics={null} />)
    expect(container.innerHTML).toBe('')
  })

  test('renders tactic cards', () => {
    render(<MITREDisplay tactics={['T1402', 'T1521', 'T1632']} />)
    expect(screen.getByText('T1402')).toBeTruthy()
    expect(screen.getByText('T1521')).toBeTruthy()
    expect(screen.getByText('T1632')).toBeTruthy()
  })

  test('shows human-readable descriptions', () => {
    render(<MITREDisplay tactics={['T1402', 'T1521']} />)
    expect(screen.getByText('Device Administration')).toBeTruthy()
    expect(screen.getByText('Command and Control')).toBeTruthy()
  })

  test('shows total tactic count in footer', () => {
    render(<MITREDisplay tactics={['T1402', 'T1521']} />)
    expect(screen.getByText('2 tactics identified')).toBeTruthy()
  })

  test('shows severity badges', () => {
    render(<MITREDisplay tactics={['T1404', 'T1402']} />)
    const criticals = screen.getAllByText('CRITICAL')
    expect(criticals.length).toBeGreaterThanOrEqual(1)
  })
})

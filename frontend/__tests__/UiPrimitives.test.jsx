import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Panel from '../src/components/ui/Panel'
import FactStrip from '../src/components/ui/FactStrip'
import VerdictChip from '../src/components/ui/VerdictChip'
import StateMessage from '../src/components/ui/StateMessage'

describe('Panel', () => {
  test('renders title and body', () => {
    render(<Panel title="Attribution"><p>body text</p></Panel>)
    expect(screen.getByRole('heading', { name: 'Attribution' })).toBeTruthy()
    expect(screen.getByText('body text')).toBeTruthy()
  })
})

describe('FactStrip', () => {
  test('shows placeholder for missing values, never 0', () => {
    render(<FactStrip facts={[{ label: 'C2', value: undefined }, { label: 'Score', value: 0 }]} />)
    expect(screen.getByText('—')).toBeTruthy()
    expect(screen.getByText('0')).toBeTruthy()
  })
})

describe('VerdictChip', () => {
  test('shows the word and score; unknown shows not yet scored', () => {
    const { rerender } = render(<VerdictChip severity="high" score={78} />)
    expect(screen.getByText('high')).toBeTruthy()
    expect(screen.getByText('78/100')).toBeTruthy()
    rerender(<VerdictChip severity="unknown" />)
    expect(screen.getByText('Not yet scored')).toBeTruthy()
  })
})

describe('StateMessage', () => {
  test('error tone is an alert; pending tone is a status', () => {
    const { unmount } = render(<StateMessage tone="error" title="Could not load" />)
    expect(screen.getByRole('alert')).toBeTruthy()
    unmount()
    render(<StateMessage tone="pending" title="Analysis running" />)
    expect(screen.getByRole('status')).toBeTruthy()
  })
})

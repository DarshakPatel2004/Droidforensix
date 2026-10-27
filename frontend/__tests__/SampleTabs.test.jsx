import { describe, test, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SampleTabs from '../src/components/SampleTabs'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'analysis', label: 'Checks' },
  { id: 'notes', label: 'Notes' },
]

describe('SampleTabs', () => {
  test('marks the active tab as selected', () => {
    render(<SampleTabs tabs={TABS} activeTab="analysis" onSelect={() => {}} />)
    expect(screen.getByRole('tab', { name: 'Checks' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: 'Overview' }).getAttribute('aria-selected')).toBe('false')
  })

  test('calls onSelect with the tab id', () => {
    const onSelect = vi.fn()
    render(<SampleTabs tabs={TABS} activeTab="overview" onSelect={onSelect} />)
    fireEvent.click(screen.getByRole('tab', { name: 'Notes' }))
    expect(onSelect).toHaveBeenCalledWith('notes')
  })

  test('disables locked tabs', () => {
    render(<SampleTabs tabs={TABS} activeTab="analysis" lockedIds={['overview', 'notes']} onSelect={() => {}} />)
    expect(screen.getByRole('tab', { name: 'Overview' }).disabled).toBe(true)
    expect(screen.getByRole('tab', { name: 'Checks' }).disabled).toBe(false)
  })
})

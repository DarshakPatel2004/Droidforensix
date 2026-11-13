import { describe, test, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SampleList from '../src/components/SampleList'
import SampleHeader from '../src/components/SampleHeader'

vi.mock('../src/api/client', () => ({ apiFetch: vi.fn(() => Promise.resolve({ status: 'confirmed' })) }))

const samples = [
  { sha256: 'aaa111', fileName: 'alpha.apk', family: 'KungFu' },
  { sha256: 'bbb222', fileName: 'beta.apk', family: 'unknown' },
]

describe('SampleList', () => {
  test('lists samples and filters by search text', () => {
    render(<SampleList samples={samples} selectedId="aaa111" backendReady onUpload={() => {}} onSelect={() => {}} />)
    expect(screen.getByText('alpha.apk')).toBeTruthy()
    expect(screen.getByText('beta.apk')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Search samples'), { target: { value: 'kung' } })
    expect(screen.queryByText('beta.apk')).toBeNull()
    expect(screen.getByText('alpha.apk').closest('button').getAttribute('aria-current')).toBe('true')
  })

  test('upload button and sample click call their handlers', () => {
    const onUpload = vi.fn()
    const onSelect = vi.fn()
    render(<SampleList samples={samples} selectedId={null} backendReady={false} onUpload={onUpload} onSelect={onSelect} />)
    fireEvent.click(screen.getByText('+ Upload APK'))
    fireEvent.click(screen.getByText('beta.apk'))
    expect(onUpload).toHaveBeenCalledTimes(1)
    expect(onSelect).toHaveBeenCalledWith(samples[1])
    expect(screen.getByText('Backend offline')).toBeTruthy()
  })
})

describe('SampleHeader', () => {
  test('shows family, analysis status and analyst status', async () => {
    render(<SampleHeader sample={samples[0]} status="completed" ready apiUrl="http://x" />)
    expect(screen.getByText('Family: KungFu')).toBeTruthy()
    expect(screen.getByText('Analysis: completed')).toBeTruthy()
    await waitFor(() => expect(screen.getByText('Analyst: confirmed')).toBeTruthy())
    expect(screen.getByText('CSV').getAttribute('href')).toContain('/threat-intel/export/csv')
  })

  test('hides exports until analysis is ready', () => {
    render(<SampleHeader sample={samples[1]} status="running" ready={false} apiUrl="http://x" />)
    expect(screen.queryByLabelText('Exports')).toBeNull()
    expect(screen.getByText('Family: No family match')).toBeTruthy()
  })
})

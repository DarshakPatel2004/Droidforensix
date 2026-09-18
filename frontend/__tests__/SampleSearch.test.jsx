import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SampleSearch from '../src/components/SampleSearch'

const MOCK_SAMPLES = [
  { sha256: 'abc123', package_name: 'com.test', family: 'XHelper' },
  { sha256: 'def456', package_name: 'com.evil', family: 'Triada' },
]

describe('SampleSearch', () => {
  beforeEach(() => vi.clearAllMocks())

  test('renders search input', () => {
    render(<SampleSearch />)
    expect(screen.getByPlaceholderText(/Search by hash/)).toBeTruthy()
  })

  test('shows samples list when provided', () => {
    render(<SampleSearch samples={MOCK_SAMPLES} />)
    expect(screen.getByText(/abc123/)).toBeTruthy()
    expect(screen.getByText(/XHelper/)).toBeTruthy()
  })

  test('calls onSelect when sample clicked', () => {
    const onSelect = vi.fn()
    render(<SampleSearch samples={MOCK_SAMPLES} onSelect={onSelect} />)
    fireEvent.click(screen.getByText(/abc123/))
    expect(onSelect).toHaveBeenCalledWith(MOCK_SAMPLES[0])
  })
})

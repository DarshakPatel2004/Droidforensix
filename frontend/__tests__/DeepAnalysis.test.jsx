import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import DeepAnalysis from '../src/components/DeepAnalysis'
import CheckCard from '../src/components/CheckCard'

describe('CheckCard', () => {
  test('shows title, tag and line', () => {
    render(<CheckCard title="Binary packing" tag="Clear" line="No packer detected" />)
    expect(screen.getByText('Binary packing')).toBeTruthy()
    expect(screen.getByText('Clear')).toBeTruthy()
    expect(screen.getByText('No packer detected')).toBeTruthy()
  })
})

describe('DeepAnalysis', () => {
  const result = {
    binary_packing: { packing_detected: false },
    native_elf_analysis: { total_libraries: 1 },
  }

  test('renders one card per check with no step numbers', () => {
    render(<DeepAnalysis result={result} />)
    expect(screen.getByRole('heading', { name: 'Deep analysis' })).toBeTruthy()
    expect(screen.getAllByRole('article')).toHaveLength(9)
    expect(screen.queryByText(/Step \d/)).toBeNull()
  })

  test('counts how many checks found something', () => {
    render(<DeepAnalysis result={result} />)
    expect(screen.getByText('1 of 9 found something')).toBeTruthy()
  })

  test('marks checks with no data as unavailable', () => {
    render(<DeepAnalysis result={result} />)
    expect(screen.getByRole('article', { name: 'Zero-day risk: Unavailable' })).toBeTruthy()
  })
})

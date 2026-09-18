import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import DissectionPage from '../src/components/DissectionPage'

vi.mock('../src/components/SmartDissection', () => ({
  default: ({ onSelectClass }) => (
    <div data-testid="mock-smart-dissection">
      Mock SmartDissection
      <button onClick={() => onSelectClass('com.example.Test')}>
        Select TestClass
      </button>
    </div>
  ),
}))

vi.mock('../src/components/ClassSourceViewer', () => ({
  default: ({ className, sampleId }) => (
    <div data-testid="mock-source-viewer">
      Source for {className} ({sampleId})
    </div>
  ),
}))

beforeEach(() => { vi.clearAllMocks() })

describe('DissectionPage', () => {
  test('shows idle state without sample', () => {
    render(<DissectionPage sample={null} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/Select a sample/)).toBeTruthy()
  })

  test('renders SmartDissection when sample provided', () => {
    render(<DissectionPage sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByTestId('mock-smart-dissection')).toBeTruthy()
  })

  test('opens source overlay on class selection', () => {
    render(<DissectionPage sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    fireEvent.click(screen.getByText('Select TestClass'))
    expect(screen.getByTestId('mock-source-viewer')).toBeTruthy()
    expect(screen.getAllByText(/com.example.Test/).length).toBeGreaterThanOrEqual(1)
  })

  test('closes source overlay on close button', () => {
    render(<DissectionPage sample={{ sha256: 'abc123' }} apiUrl="http://localhost:8000" />)
    fireEvent.click(screen.getByText('Select TestClass'))
    expect(screen.getByTestId('mock-source-viewer')).toBeTruthy()
    fireEvent.click(screen.getByText('Close'))
    expect(screen.queryByTestId('mock-source-viewer')).toBeNull()
  })
})

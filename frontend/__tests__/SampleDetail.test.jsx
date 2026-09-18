import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SampleDetail from '../src/pages/SampleDetail'

vi.mock('../src/components/ThreatSummary', () => ({ default: () => <div>ThreatSummary</div> }))
vi.mock('../src/components/AttributionEvidence', () => ({ default: () => <div>AttributionEvidence</div> }))
vi.mock('../src/components/RelatedSamples', () => ({ default: ({ onSelect }) => <div><button onClick={() => onSelect?.('related-001')}>Select Related</button></div> }))
vi.mock('../src/components/DissectionTabs', () => ({ default: () => <div>DissectionTabs</div> }))

beforeEach(() => { vi.clearAllMocks() })

describe('SampleDetail', () => {
  test('shows empty state without sampleId', () => {
    render(<SampleDetail sample={{}} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('No Sample Selected')).toBeTruthy()
  })

  test('renders sample name and hash', () => {
    render(<SampleDetail sample={{ sampleId: 'abc123', sha256: 'abc123def456', fileName: 'malware.apk' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/malware\.apk/)).toBeTruthy()
  })

  test('renders all section buttons', () => {
    render(<SampleDetail sample={{ sampleId: 'abc123' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Threat Summary')).toBeTruthy()
    expect(screen.getByText('Attribution')).toBeTruthy()
    expect(screen.getByText('Investigation')).toBeTruthy()
    expect(screen.getByText('Related')).toBeTruthy()
  })

  test('defaults to threat summary section', () => {
    render(<SampleDetail sample={{ sampleId: 'abc123' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText('ThreatSummary')).toBeTruthy()
  })

  test('switches to attribution section', () => {
    render(<SampleDetail sample={{ sampleId: 'abc123' }} apiUrl="http://localhost:8000" />)
    fireEvent.click(screen.getByText('Attribution'))
    expect(screen.getByText('AttributionEvidence')).toBeTruthy()
  })

  test('switches to investigation section', () => {
    render(<SampleDetail sample={{ sampleId: 'abc123' }} apiUrl="http://localhost:8000" />)
    fireEvent.click(screen.getByText('Investigation'))
    expect(screen.getByText('DissectionTabs')).toBeTruthy()
  })

  test('switches to related section and calls onSelectSample', () => {
    const onSelect = vi.fn()
    render(<SampleDetail sample={{ sampleId: 'abc123' }} apiUrl="http://localhost:8000" onSelectSample={onSelect} />)
    fireEvent.click(screen.getByText('Related'))
    fireEvent.click(screen.getByText('Select Related'))
    expect(onSelect).toHaveBeenCalledWith({ sampleId: 'related-001' })
  })
})

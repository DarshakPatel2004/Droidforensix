import { describe, test, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ThreatConsolidationSummary from '../src/components/ThreatConsolidationSummary'

const MOCK_REPORT = {
  sample_id: 'abc123',
  final_classification: 'malware',
  llm_assessment: {
    severity: 'critical',
    confidence: 0.92,
    risk_score: 85,
    classification: 'malware',
    llm_synthesis: {
      reasoning: 'Reflection and payload drop patterns detected',
      mitre_tactics: ['T1402', 'T1521'],
      behavioral_analysis: 'Hides in system processes',
      recommended_actions: ['Block package', 'Sinkhole C2'],
    },
  },
}

describe('ThreatConsolidationSummary', () => {
  test('shows no report state when null', () => {
    render(<ThreatConsolidationSummary report={null} />)
    expect(screen.getByText('No report available')).toBeTruthy()
  })

  test('renders classification header', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText(/MALWARE/)).toBeTruthy()
  })

  test('shows confidence and risk score', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getAllByText(/HIGH/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/85\/100/)).toBeTruthy()
  })

  test('shows stage consensus', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText(/Stage Consensus/)).toBeTruthy()
  })

  test('renders LLM synthesis section', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText(/Reflection and payload drop/)).toBeTruthy()
  })

  test('renders MITRE tactics from synthesis', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText('T1402')).toBeTruthy()
    expect(screen.getByText('T1521')).toBeTruthy()
  })

  test('renders recommended actions', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText('Block package')).toBeTruthy()
    expect(screen.getByText('Sinkhole C2')).toBeTruthy()
  })

  test('toggles section expand/collapse', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText(/LLM Synthesis/)).toBeTruthy()
    fireEvent.click(screen.getByText(/LLM Synthesis/))
    expect(screen.queryByText(/Reflection and payload drop/)).toBeNull()
  })

  test('shows download button when handler provided', () => {
    const onDownload = () => {}
    render(<ThreatConsolidationSummary report={MOCK_REPORT} onDownloadReport={onDownload} />)
    expect(screen.getByText(/Download PDF Report/)).toBeTruthy()
  })

  test('shows case ID in footer', () => {
    render(<ThreatConsolidationSummary report={MOCK_REPORT} />)
    expect(screen.getByText(/abc123/)).toBeTruthy()
  })
})

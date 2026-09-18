import { describe, test, expect } from 'vitest'
import {
  formatDuration,
  truncateHash,
  formatTimestamp,
  riskColor,
  riskBg,
  severityFromScore,
  entropyLabel,
} from '../src/utils/formatters'

describe('formatDuration', () => {
  test('returns em dash for null/undefined', () => {
    expect(formatDuration(null)).toBe('\u2014')
    expect(formatDuration(undefined)).toBe('\u2014')
  })
  test('returns 0s for 0', () => { expect(formatDuration(0)).toBe('0s') })
  test('formats seconds only', () => { expect(formatDuration(45)).toBe('45s') })
  test('formats minutes and seconds', () => { expect(formatDuration(125)).toBe('2m 5s') })
  test('formats hours and minutes', () => { expect(formatDuration(3661)).toBe('1h 1m 1s') })
})

describe('truncateHash', () => {
  test('returns empty for null/undefined', () => {
    expect(truncateHash(null)).toBe('')
    expect(truncateHash(undefined)).toBe('')
  })
  test('truncates long hash', () => {
    const hash = 'abcdef1234567890abcdef1234567890'
    expect(truncateHash(hash, 8)).toBe('abcdef12\u2026')
  })
  test('returns short hash unchanged', () => {
    expect(truncateHash('abc', 16)).toBe('abc')
  })
})

describe('formatTimestamp', () => {
  test('returns empty for null/undefined', () => {
    expect(formatTimestamp(null)).toBe('')
    expect(formatTimestamp(undefined)).toBe('')
  })
  test('formats ISO string', () => {
    const result = formatTimestamp('2024-01-15T10:30:00Z')
    expect(result).toBeTruthy()
    expect(typeof result).toBe('string')
  })
})

describe('riskColor', () => {
  test('returns correct colors', () => {
    expect(riskColor('CRITICAL')).toBe('var(--accent-rose)')
    expect(riskColor('HIGH')).toBe('var(--accent-amber)')
    expect(riskColor('MEDIUM')).toBe('var(--accent-cyan)')
    expect(riskColor('LOW')).toBe('var(--accent-emerald)')
  })
  test('returns default for unknown', () => {
    expect(riskColor('UNKNOWN')).toBe('var(--text-muted)')
  })
})

describe('riskBg', () => {
  test('returns correct backgrounds', () => {
    expect(riskBg('CRITICAL')).toContain('244,63,94')
    expect(riskBg('HIGH')).toContain('245,158,11')
    expect(riskBg('MEDIUM')).toContain('6,182,212')
    expect(riskBg('LOW')).toContain('16,185,129')
  })
  test('returns default for unknown', () => {
    expect(riskBg('UNKNOWN')).toContain('148,163,184')
  })
})

describe('severityFromScore', () => {
  test('returns CRITICAL for >= 75', () => { expect(severityFromScore(75)).toBe('CRITICAL') })
  test('returns HIGH for >= 50', () => { expect(severityFromScore(50)).toBe('HIGH') })
  test('returns MEDIUM for >= 25', () => { expect(severityFromScore(25)).toBe('MEDIUM') })
  test('returns LOW for < 25', () => { expect(severityFromScore(0)).toBe('LOW') })
})

describe('entropyLabel', () => {
  test('returns High for > 7', () => { expect(entropyLabel(8)).toEqual({ label: 'High', color: 'var(--accent-rose)' }) })
  test('returns Moderate for > 5', () => { expect(entropyLabel(6)).toEqual({ label: 'Moderate', color: 'var(--accent-amber)' }) })
  test('returns Normal for <= 5', () => { expect(entropyLabel(3)).toEqual({ label: 'Normal', color: 'var(--accent-emerald)' }) })
})

import { describe, test, expect } from 'vitest'
import { summarizeChecks, needsAttention } from '../src/utils/checkSummaries'

const CLEAN_RESULT = {
  binary_packing: { packing_detected: false },
  string_clustering: { total_clusters: 0 },
  reflective_tracing: { total_reflective_calls: 0 },
  native_elf_analysis: { total_libraries: 0 },
  network_protocols: { total_c2: 0, total_suspicious: 0 },
  permission_correlation: { total_used: 0, total_permissions: 8 },
  certificate_analysis: { certificate_found: true, known_bad: false, warnings: [] },
  family_clustering: { best_match: null },
  threat_synthesis: { zero_day_risk_score: 0, risk_level: 'none' },
  threat_chains: [],
}

const byKey = (checks, key) => checks.find((c) => c.key === key)

describe('summarizeChecks', () => {
  test('returns nine checks in order', () => {
    const checks = summarizeChecks(CLEAN_RESULT)
    expect(checks).toHaveLength(9)
    expect(checks[0].key).toBe('binary_packing')
    expect(checks[8].key).toBe('threat_synthesis')
  })

  test('a clean sample has no findings', () => {
    const checks = summarizeChecks(CLEAN_RESULT)
    expect(checks.filter((c) => c.tag === 'Finding')).toHaveLength(0)
    expect(byKey(checks, 'permission_correlation').line).toBe('8 declared, none seen used in code')
  })

  test('native libraries are a finding with a count', () => {
    const checks = summarizeChecks({ ...CLEAN_RESULT, native_elf_analysis: { total_libraries: 1 } })
    expect(byKey(checks, 'native_elf_analysis')).toMatchObject({ tag: 'Finding', line: '1 native library file' })
  })

  test('a missing check is marked unavailable, not clear', () => {
    const withoutPacking = { ...CLEAN_RESULT }
    delete withoutPacking.binary_packing
    const checks = summarizeChecks(withoutPacking)
    expect(byKey(checks, 'binary_packing').tag).toBe('Unavailable')
  })

  test('zero-day risk at medium or above is a finding', () => {
    const checks = summarizeChecks({ ...CLEAN_RESULT, threat_synthesis: { zero_day_risk_score: 60, risk_level: 'medium' } })
    expect(byKey(checks, 'threat_synthesis')).toMatchObject({ tag: 'Finding', line: 'Zero-day risk 60/100' })
  })
})

describe('needsAttention', () => {
  test('nothing to flag on a clean sample', () => {
    expect(needsAttention(CLEAN_RESULT, 0)).toEqual([])
  })

  test('lists unique C2 indicators when present', () => {
    const items = needsAttention(CLEAN_RESULT, 8)
    expect(items[0]).toMatchObject({ tag: 'C2', text: '8 unique C2 indicators found' })
  })

  test('uses singular for one indicator', () => {
    expect(needsAttention(CLEAN_RESULT, 1)[0].text).toBe('1 unique C2 indicator found')
  })

  test('flags medium-or-higher threat chains only', () => {
    const result = {
      ...CLEAN_RESULT,
      threat_chains: [{ severity: 'medium' }, { severity: 'low' }, { severity: 'high' }],
    }
    const chain = needsAttention(result, 0).find((i) => i.tag === 'Chain')
    expect(chain.text).toBe('2 threat chains at medium severity or higher')
  })

  test('turns each finding into an attention item', () => {
    const result = { ...CLEAN_RESULT, native_elf_analysis: { total_libraries: 2 } }
    expect(needsAttention(result, 0)).toContainEqual({
      tag: 'Check',
      level: 'warn',
      text: 'Native libraries: 2 native library files',
    })
  })

  test('flags manual review', () => {
    expect(needsAttention({ ...CLEAN_RESULT, needs_manual_review: true }, 0)).toContainEqual({
      tag: 'Review',
      level: 'info',
      text: 'Flagged for manual review',
    })
  })
})

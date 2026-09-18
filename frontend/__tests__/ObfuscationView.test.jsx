import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ObfuscationView from '../src/components/ObfuscationView'

const MOCK_OBF = {
  obfuscation_score: 50,
  obfuscation_level: 'medium',
  techniques: [
    { name: 'xor_single', items: [{ class: 'com.example.CryptoHelper', score: 0.85, key: '0x42' }] },
  ],
  elf_analysis: [],
  summary: { total_strings: 50, deobfuscated: 12, techniques_used: ['xor_single'] },
}

beforeEach(() => { vi.clearAllMocks() })

describe('ObfuscationView', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ObfuscationView sample={{ sha256: 'test-001' }} apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/Loading Obfuscation Analysis/)).toBeTruthy()
  })

  test('renders obfuscation data on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_OBF) })
    render(<ObfuscationView sample={{ sha256: 'test-001' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/XOR/)).toBeTruthy()
    })
  })

  test('shows obfuscation score', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_OBF) })
    render(<ObfuscationView sample={{ sha256: 'test-001' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/50\/100/)).toBeTruthy()
    })
  })

  test('shows error state on failed fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 })
    render(<ObfuscationView sample={{ sha256: 'test-001' }} apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Failed to load obfuscation analysis/)).toBeTruthy()
    })
  })
})

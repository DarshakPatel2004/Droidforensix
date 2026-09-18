import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import PermissionsTab from '../src/components/tabs/PermissionsTab'

const MOCK_PERMS = {
  permissions: [
    { name: 'android.permission.SEND_SMS', protection_level: 'dangerous' },
    { name: 'android.permission.INTERNET', protection_level: 'normal' },
    { name: 'android.permission.READ_SMS', protection_level: 'dangerous' },
  ],
}

beforeEach(() => { vi.clearAllMocks() })

describe('PermissionsTab', () => {
  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<PermissionsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading permissions...')).toBeTruthy()
  })

  test('renders permissions on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_PERMS) })
    render(<PermissionsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('android.permission.SEND_SMS')).toBeTruthy()
      expect(screen.getByText('android.permission.INTERNET')).toBeTruthy()
    })
  })

  test('shows count buttons for each risk level', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_PERMS) })
    render(<PermissionsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/All \(3\)/)).toBeTruthy()
      expect(screen.getByText(/Dangerous \(2\)/)).toBeTruthy()
      expect(screen.getByText(/Normal \(1\)/)).toBeTruthy()
    })
  })

  test('filters by risk level on button click', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(MOCK_PERMS) })
    render(<PermissionsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => { expect(screen.getByText(/All \(3\)/)).toBeTruthy() })
    fireEvent.click(screen.getByText(/Normal \(1\)/))
    await waitFor(() => {
      expect(screen.queryByText('android.permission.SEND_SMS')).toBeNull()
      expect(screen.getByText('android.permission.INTERNET')).toBeTruthy()
    })
  })

  test('shows empty state when no permissions', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ permissions: [] }) })
    render(<PermissionsTab sampleId="test-001" apiUrl="http://localhost:8000" />)
    await waitFor(() => expect(screen.getByText('No permissions declared')).toBeTruthy())
  })
})

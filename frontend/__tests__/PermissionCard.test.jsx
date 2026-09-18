import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import PermissionCard from '../src/components/PermissionCard'

describe('PermissionCard', () => {
  test('renders name and protection level', () => {
    render(<PermissionCard name="android.permission.SEND_SMS" protectionLevel="dangerous" />)
    expect(screen.getByText('android.permission.SEND_SMS')).toBeTruthy()
    expect(screen.getByText('dangerous')).toBeTruthy()
  })

  test('shows label when provided', () => {
    render(<PermissionCard name="READ_CONTACTS" label="Read your contacts" protectionLevel="dangerous" />)
    expect(screen.getByText('Read your contacts')).toBeTruthy()
  })

  test('shows description when no label', () => {
    render(<PermissionCard name="INTERNET" description="Full network access" protectionLevel="normal" />)
    expect(screen.getByText('Full network access')).toBeTruthy()
  })

  test('defaults to normal style for unknown protection level', () => {
    render(<PermissionCard name="UNKNOWN_PERM" protectionLevel="unknown" />)
    expect(screen.getByText('unknown')).toBeTruthy()
  })
})

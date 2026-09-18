import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import ComponentCard from '../src/components/ComponentCard'

describe('ComponentCard', () => {
  test('renders name and type', () => {
    render(<ComponentCard name="com.example.MainActivity" type="activity" />)
    expect(screen.getByText('com.example.MainActivity')).toBeTruthy()
    expect(screen.getByText('activity')).toBeTruthy()
  })

  test('shows exported badge when exported=true', () => {
    render(<ComponentCard name="TestService" type="service" exported />)
    expect(screen.getByText('Exported')).toBeTruthy()
  })

  test('shows not exported badge when exported=false', () => {
    render(<ComponentCard name="TestService" type="service" exported={false} />)
    expect(screen.getByText('Not Exported')).toBeTruthy()
  })

  test('hides exported badge when exported undefined', () => {
    render(<ComponentCard name="Test" type="activity" />)
    expect(screen.queryByText('Exported')).toBeNull()
    expect(screen.queryByText('Not Exported')).toBeNull()
  })

  test('renders intent filters', () => {
    render(<ComponentCard name="Test" type="receiver" intentFilters={['android.intent.action.BOOT_COMPLETED', 'android.intent.action.SMS_RECEIVED']} />)
    expect(screen.getByText('android.intent.action.BOOT_COMPLETED')).toBeTruthy()
    expect(screen.getByText('android.intent.action.SMS_RECEIVED')).toBeTruthy()
  })
})

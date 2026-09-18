import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { ToastProvider, useToast } from '../src/components/Toast'

vi.useFakeTimers()

function TestHarness() {
  const { addToast } = useToast()
  return (
    <div>
      <button onClick={() => addToast('Hello', 'success')}>Add Success</button>
      <button onClick={() => addToast('Warning!', 'warning')}>Add Warning</button>
      <button onClick={() => addToast('Error!', 'error', { duration: 0 })}>Add Error</button>
    </div>
  )
}

function renderWithToast(ui) {
  return render(<ToastProvider>{ui}</ToastProvider>)
}

beforeEach(() => { vi.clearAllMocks() })
afterEach(() => { vi.runOnlyPendingTimers() })

describe('ToastProvider / useToast', () => {
  test('renders children', () => {
    renderWithToast(<div>child</div>)
    expect(screen.getByText('child')).toBeTruthy()
  })

  test('adds success toast with auto-dismiss', () => {
    renderWithToast(<TestHarness />)
    fireEvent.click(screen.getByText('Add Success'))
    expect(screen.getByText('Hello')).toBeTruthy()
    expect(screen.getByText('✅')).toBeTruthy()

    act(() => { vi.advanceTimersByTime(3000) })
    expect(screen.queryByText('Hello')).toBeNull()
  })

  test('adds warning toast with 8s auto-dismiss', () => {
    renderWithToast(<TestHarness />)
    fireEvent.click(screen.getByText('Add Warning'))
    expect(screen.getByText('Warning!')).toBeTruthy()

    act(() => { vi.advanceTimersByTime(8000) })
    expect(screen.queryByText('Warning!')).toBeNull()
  })

  test('error toast persists without duration', () => {
    renderWithToast(<TestHarness />)
    fireEvent.click(screen.getByText('Add Error'))
    expect(screen.getByText('Error!')).toBeTruthy()

    act(() => { vi.advanceTimersByTime(10000) })
    expect(screen.getByText('Error!')).toBeTruthy()
  })

  test('dismisses toast on close button click', () => {
    renderWithToast(<TestHarness />)
    fireEvent.click(screen.getByText('Add Success'))

    const dismissButtons = screen.getAllByLabelText('Dismiss')
    fireEvent.click(dismissButtons[0])

    expect(screen.queryByText('Hello')).toBeNull()
  })

  test('shows correct icons per type', () => {
    renderWithToast(<TestHarness />)
    fireEvent.click(screen.getByText('Add Error'))
    expect(screen.getByText('❌')).toBeTruthy()
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import ClassSourceViewer from '../src/components/ClassSourceViewer'

beforeEach(() => { vi.clearAllMocks() })

describe('ClassSourceViewer', () => {
  test('shows empty state without class name', () => {
    render(<ClassSourceViewer sampleId="test-001" className="" apiUrl="http://localhost:8000" />)
    expect(screen.getByText(/Select a class/)).toBeTruthy()
  })

  test('shows loading state', () => {
    global.fetch = vi.fn(() => new Promise(() => {}))
    render(<ClassSourceViewer sampleId="test-001" className="com.example.Test" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Loading source…')).toBeTruthy()
  })

  test('renders source code on success', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ code: 'public class Test {}' }) })
    render(<ClassSourceViewer sampleId="test-001" className="com.example.Test" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('public class Test {}')).toBeTruthy()
    })
  })

  test('shows error on failed fetch', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 })
    render(<ClassSourceViewer sampleId="test-001" className="com.example.Test" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText(/Error loading source/)).toBeTruthy()
    })
  })

  test('shows class name in header', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ code: 'code' }) })
    render(<ClassSourceViewer sampleId="test-001" className="com.example.MyActivity" apiUrl="http://localhost:8000" />)
    await waitFor(() => {
      expect(screen.getByText('com.example.MyActivity')).toBeTruthy()
    })
  })
})

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SmartDissection from '../src/components/SmartDissection'

/**
 * P2-B1 (stored XSS): highlightSyntax() passed attacker-controlled DEX text to
 * dangerouslySetInnerHTML after wrapping only 13 hardcoded keywords in <span>.
 * The rest of the line was never escaped. Every string in the analysed APK is
 * chosen by the malware author, so a DEX method body containing markup executed
 * in the analyst's browser session when they expanded the class card.
 *
 * These tests assert the security property: markup from a method body must reach
 * the DOM as text, never as live elements.
 */

const XSS_METHODS = {
  methods: [
    {
      name: 'onCreate',
      body: 'const x = "<img src=x onerror=alert(1)>";',
    },
  ],
}

const MOCK_CLASSES = {
  classes: [
    { name: 'com.evil.Payload', method_names: ['onCreate'], method_count: 1 },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()
})

/** Render the viewer with a method body containing markup, and expand it. */
async function renderWithBody(body) {
  // The component fetches two things on mount (classes + obfuscation), then
  // method bodies per expanded class. Route by URL so the queue cannot run dry
  // (an earlier version using mockResolvedValueOnce surfaced as a null .then).
  const METHOD_BODY = body
  global.fetch = vi.fn((url) => {
    if (url.includes('/dissection/classes')) {
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(MOCK_CLASSES) })
    }
    if (url.includes('/class-methods/')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ methods: [{ name: 'onCreate', body: METHOD_BODY }] }),
      })
    }
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) })
  })

  const { container } = render(
    <SmartDissection sample={{ sha256: 'abc' }} apiUrl="http://localhost:8000" />
  )

  await waitFor(() => expect(screen.getByText(/Payload/)).toBeTruthy())

  // Expand the class card. The method fetch fires from the component's own
  // effect, so just expanding the class is enough to render the body.
  fireEvent.click(screen.getByText(/Payload/))

  // The methods resolve in an effect; wait for the body to reach the DOM before
  // asserting, otherwise this races the fetch.
  await waitFor(() => expect(global.fetch).toHaveBeenCalledWith(
    expect.stringContaining('/class-methods/')
  ))
  await waitFor(() => expect(container.textContent).toContain('onCreate'))

  return container
}

describe('SmartDissection XSS hardening (P2-B1)', () => {
  test('an img/onerror payload from a method body never becomes a live element', async () => {
    const container = await renderWithBody(XSS_METHODS.methods[0].body)

    // The payload must not have produced an element.
    expect(container.querySelector('img')).toBeNull()

    // It must still be visible as literal text.
    await waitFor(() =>
      expect(container.textContent).toContain('<img src=x onerror=alert(1)>')
    )
  })

  test('a script tag from a method body is not executable markup', async () => {
    const container = await renderWithBody('const s = "<script>alert(1)</script>";')

    expect(container.querySelector('script')).toBeNull()
    await waitFor(() => expect(container.textContent).toContain('<script>alert(1)</script>'))
  })

  test('an svg/onload payload is neutralised', async () => {
    const container = await renderWithBody('v = "<svg onload=alert(1)>";')

    expect(container.querySelector('svg')).toBeNull()
    await waitFor(() => expect(container.textContent).toContain('<svg onload=alert(1)>'))
  })

  test('suspicious keywords are still highlighted, so the feature survives', async () => {
    const container = await renderWithBody('Cipher.getInstance("AES") // suspicious: encrypt')

    // The keyword highlighting is the whole point of highlightSyntax; the fix
    // must escape without breaking it.
    await waitFor(() =>
      expect(container.querySelectorAll('span.code-keyword').length).toBeGreaterThan(0)
    )
  })

  test('the code viewer contains no unescaped-angle-bracket elements from the body', async () => {
    const container = await renderWithBody('x = "<b>bold</b>";')

    expect(container.querySelector('b')).toBeNull()
    await waitFor(() => expect(container.textContent).toContain('<b>bold</b>'))
  })
})
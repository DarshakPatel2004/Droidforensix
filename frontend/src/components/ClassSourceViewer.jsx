import { useState, useEffect, useRef } from 'react'
import hljs from 'highlight.js/lib/core'
import java from 'highlight.js/lib/languages/java'
import xml from 'highlight.js/lib/languages/xml'
import '../styles/ClassSourceViewer.css'
import 'highlight.js/styles/github-dark.min.css'

hljs.registerLanguage('java', java)
hljs.registerLanguage('xml', xml)

// Above this size, hljs.highlightElement blocks the tab for seconds.
const HIGHLIGHT_MAX_CHARS = 200 * 1024

// Wraps matches in text nodes only, so hljs markup is never split or altered.
function markMatches(root, term) {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const splitter = new RegExp(`(${escaped})`, 'i')
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
  const textNodes = []
  while (walker.nextNode()) textNodes.push(walker.currentNode)

  for (const node of textNodes) {
    const parts = node.data.split(splitter)
    if (parts.length === 1) continue
    const fragment = document.createDocumentFragment()
    // With one capture group, odd indices are the matches.
    parts.forEach((part, index) => {
      if (!part) return
      if (index % 2 === 1) {
        const mark = document.createElement('mark')
        mark.className = 'source-highlight'
        mark.textContent = part
        fragment.append(mark)
      } else {
        fragment.append(part)
      }
    })
    node.replaceWith(fragment)
  }
}

export default function ClassSourceViewer({ sampleId, className, apiUrl, highlight }) {
  const [source, setSource] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const codeRef = useRef(null)

  const API_URL = apiUrl || 'http://localhost:8000'

  useEffect(() => {
    const el = codeRef.current
    if (!el || !source) return

    // Reset from the source string, not cached markup. React owns this node.
    el.textContent = source
    if (source.length <= HIGHLIGHT_MAX_CHARS) {
      hljs.highlightElement(el)
    }
    if (highlight) {
      markMatches(el, highlight)
    }
  }, [source, highlight])

  useEffect(() => {
    if (!sampleId || !className) {
      return
    }

    let stale = false
    const controller = new AbortController()

    const fetchSource = async () => {
      setLoading(true)
      setError(null)
      try {
        const encoded = encodeURIComponent(className)
        const response = await fetch(
          `${API_URL}/api/sample/${sampleId}/dissection/code/${encoded}`,
          { signal: controller.signal }
        )
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (stale) return
        setSource(data.code || '')
      } catch (err) {
        if (stale || err.name === 'AbortError') return
        setError(err.message)
      } finally {
        if (!stale) setLoading(false)
      }
    }

    fetchSource()
    return () => {
      stale = true
      controller.abort()
    }
  }, [sampleId, className, API_URL])

  if (!className) {
    return (
      <div className="source-viewer empty">
        <p>Select a class from the list to view its decompiled source.</p>
      </div>
    )
  }

  return (
    <div className="source-viewer">
      <div className="source-header">
        <h4 className="source-class-name text-mono">{className}</h4>
      </div>
      {loading && <div className="source-loading">Loading source…</div>}
      {error && <div className="source-error">Error loading source: {error}</div>}
      {!loading && !error && source !== null && (
        <pre className="source-code">
          <code ref={codeRef} className="language-java">{source}</code>
        </pre>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'

export default function DEXTab({ sampleId, apiUrl }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!sampleId) return
    fetch(`${apiUrl}/api/sample/${sampleId}/dissection/dex`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { setData(d.dex_stats); setLoading(false) })
      .catch(() => setLoading(false))
  }, [sampleId, apiUrl])

  if (loading) return <div className="empty-state">Loading DEX data...</div>
  if (!data) return <div className="empty-state">No DEX data available</div>

  const rows = [
    { label: 'DEX Files', value: data.dex_count ?? 'N/A' },
    { label: 'Total Classes', value: data.total_classes ?? 'N/A' },
    { label: 'Total Methods', value: data.total_methods ?? 'N/A' },
    { label: 'Total Strings', value: data.total_strings ?? 'N/A' },
    { label: 'Total Bytes', value: data.total_bytes ?? 'N/A' },
    { label: 'Is Multidex', value: data.is_multidex !== undefined ? (data.is_multidex ? 'Yes' : 'No') : 'N/A' },
  ]

  const entropy = typeof data.entropy === 'number' ? data.entropy : null
  const entropyColor = entropy > 7 ? '#f43f5e' : entropy > 5 ? '#f59e0b' : '#10b981'
  const entropyLabel = entropy > 7
    ? 'High entropy — DEX content is likely packed or encrypted'
    : entropy > 5
      ? 'Moderate entropy — partially compressed or obfuscated content'
      : 'Normal entropy — plain DEX bytecode'
  const entropyPie = entropy !== null ? [
    { name: 'Entropy', value: entropy },
    { name: 'Remaining', value: 8 - entropy },
  ] : []

  const dexFiles = Array.isArray(data.dex_files) ? data.dex_files : []

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
        {rows.map((r, i) => (
          <div key={i} className="card" style={{ padding: '14px 16px', textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{r.label}</div>
            <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {r.value}
            </div>
          </div>
        ))}
      </div>

      {entropy !== null && (
        <div className="card" style={{ padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            DEX Entropy
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
            <div style={{ width: 100, height: 100 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={entropyPie}
                    cx="50%" cy="50%"
                    innerRadius={30}
                    outerRadius={45}
                    startAngle={180}
                    endAngle={0}
                    dataKey="value"
                  >
                    {entropyPie.map((entry, idx) => (
                      <Cell key={idx} fill={idx === 0 ? entropyColor : 'rgba(148,163,184,0.1)'} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div>
              <div style={{ fontSize: 28, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: entropyColor }}>
                {entropy.toFixed(2)}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                bits per byte (scale 0–8)
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                {entropyLabel}
              </div>
            </div>
          </div>

          <div style={{ marginTop: 16, padding: '12px 14px', borderRadius: 6, background: 'var(--bg-secondary)', fontSize: 12, lineHeight: 1.7, color: 'var(--text-secondary)' }}>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>How is this computed?</div>
            <div>
              Shannon entropy over the <strong>raw (uncompressed) bytes of all DEX files concatenated</strong>, measured in
              bits per byte: <span className="text-mono" style={{ fontSize: 11 }}>H = −Σ p(b)·log₂(p(b))</span>, where p(b) is the
              probability of byte value b (0–255) appearing in the data.
            </div>
            <div style={{ marginTop: 6 }}>
              <strong>Interpretation thresholds:</strong>
            </div>
            <ul style={{ margin: '4px 0 0 18px', padding: 0 }}>
              <li><span style={{ color: '#f43f5e' }}>H &gt; 7.0</span> — near-random bytes; consistent with packing / encryption / compression of the DEX content (legitimate apps rarely exceed this).</li>
              <li><span style={{ color: '#f59e0b' }}>5.0 &lt; H ≤ 7.0</span> — moderately irregular; mixed plain code with compressed or obfuscated sections.</li>
              <li><span style={{ color: '#10b981' }}>H ≤ 5.0</span> — typical for normal, uncompressed DEX bytecode.</li>
            </ul>
            <div style={{ marginTop: 6, color: 'var(--text-muted)' }}>
              Note: this is the combined DEX entropy; per-file values below show which DEX drives the aggregate. High entropy
              alone is not conclusive — the binary-packing analysis (obfuscation step) combines it with other signals
              (string sparsity, class counts, native libraries) before flagging packing.
            </div>
          </div>
        </div>
      )}

      {dexFiles.length > 0 && (
        <div className="card" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10 }}>
            Per-File Breakdown
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr>
                  {['#', 'Size', 'Classes', 'Methods', 'Strings', 'Entropy'].map(h => (
                    <th key={h} style={{
                      textAlign: 'left', padding: '8px 10px', fontSize: 10, fontWeight: 700,
                      textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)',
                      borderBottom: '1px solid var(--border-color)', whiteSpace: 'nowrap',
                      background: 'var(--bg-secondary)',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dexFiles.map((f, i) => {
                  const fColor = f.entropy > 7 ? '#f43f5e' : f.entropy > 5 ? '#f59e0b' : '#10b981'
                  return (
                    <tr key={i} style={{ background: i % 2 === 0 ? 'transparent' : 'var(--bg-secondary)' }}>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                        {f.index === 0 ? 'classes.dex' : `classes${f.index + 1}.dex`}
                      </td>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                        {(f.size / 1024 / 1024).toFixed(2)} MB
                      </td>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{f.classes}</td>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{f.methods}</td>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{f.strings}</td>
                      <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border-color)', fontWeight: 700, color: fColor, fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                        {f.entropy?.toFixed(4) ?? '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

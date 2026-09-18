export default function LoadingSpinner({ message, size = 'md' }) {
  const height = size === 'sm' ? 4 : size === 'lg' ? 8 : 6
  return (
    <div style={{ padding: '2rem 0', textAlign: 'center' }}>
      <div style={{
        width: '100%', maxWidth: 320, margin: '0 auto', height,
        borderRadius: height, background: 'rgba(148,163,184,0.1)',
        overflow: 'hidden', position: 'relative',
      }}>
        <div style={{
          width: '40%', height: '100%', borderRadius: height,
          background: 'linear-gradient(90deg, var(--cyan), var(--violet))',
          animation: 'shimmer 1.5s ease-in-out infinite',
          backgroundSize: '200% 100%',
        }} />
      </div>
      {message && (
        <div style={{ marginTop: 12, fontSize: 13, color: 'var(--text-muted)' }}>{message}</div>
      )}
    </div>
  )
}

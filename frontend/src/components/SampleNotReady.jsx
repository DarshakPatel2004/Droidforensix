const MESSAGES = {
  uploaded: 'Upload received. Analysis has not started yet.',
  queued: 'Queued for analysis.',
  analyzing: 'Analysing. This page fills in when the analysis finishes.',
}

// Shown in place of a sample tab until its analysis has completed.
export default function SampleNotReady({ status, error }) {
  if (status === 'failed') {
    return (
      <div className="empty-state" role="alert">
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>Analysis failed</div>
        <div style={{ fontSize: 13 }}>{error || 'The pipeline stopped with an error.'}</div>
      </div>
    )
  }

  // No status and an error: the sample could not be found, so there is nothing to wait for.
  if (!status && error) {
    return (
      <div className="empty-state" role="alert">
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>Cannot load this sample</div>
        <div style={{ fontSize: 13 }}>{error}</div>
      </div>
    )
  }

  return (
    <div className="empty-state" role="status">
      <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>Analysis in progress</div>
      <div style={{ fontSize: 13 }}>{MESSAGES[status] || 'Checking analysis status…'}</div>
    </div>
  )
}

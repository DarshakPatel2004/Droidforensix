// Empty, error and not-ready states share one layout. tone: 'empty' | 'error' | 'pending'.
export default function StateMessage({ tone = 'empty', title, detail, role }) {
  return (
    <div className={`ui-state is-${tone}`} role={role || (tone === 'error' ? 'alert' : 'status')}>
      <p className="ui-state-title">{title}</p>
      {detail && <p className="ui-state-detail">{detail}</p>}
    </div>
  )
}

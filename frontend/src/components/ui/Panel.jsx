// Bordered surface with an optional heading. The only container the viewer uses for grouped content.
export default function Panel({ title, actions, children, ariaLabel }) {
  return (
    <section className="ui-panel" aria-label={title ? undefined : ariaLabel}>
      {(title || actions) && (
        <header className="ui-panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="ui-panel-actions">{actions}</div>}
        </header>
      )}
      <div className="ui-panel-body">{children}</div>
    </section>
  )
}

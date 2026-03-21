import React from 'react';

const joinClassNames = (...values) => values.filter(Boolean).join(' ');

export function StatusBadge({ tone = 'ok', className = '', children, ...props }) {
  return (
    <span className={joinClassNames('pill', tone, className)} {...props}>
      {children}
    </span>
  );
}

export function SectionCard({ title, subtitle = '', actions = null, className = '', children }) {
  return (
    <section className={joinClassNames('panel', 'reveal', 'section-card', className)}>
      {(title || subtitle || actions) && (
        <div className="panel-header compact-header">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <p className="muted">{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function MetricTile({ label, value, icon = '', tone = '', className = '' }) {
  return (
    <article className={joinClassNames('metric-tile', tone, className)}>
      {icon ? <span className="metric-tile-icon" aria-hidden="true">{icon}</span> : null}
      <div>
        <strong>{value}</strong>
        <span>{label}</span>
      </div>
    </article>
  );
}

export function EmptyState({ title, message = '', action = null, className = '' }) {
  return (
    <div className={joinClassNames('empty-state', className)}>
      <strong>{title}</strong>
      {message ? <p className="muted">{message}</p> : null}
      {action}
    </div>
  );
}

export function InlineAlert({ tone = 'info', children, className = '' }) {
  return <div className={joinClassNames('inline-alert', tone, className)}>{children}</div>;
}

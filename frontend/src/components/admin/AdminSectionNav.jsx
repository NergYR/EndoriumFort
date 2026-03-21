import React from 'react';
import { StatusBadge } from '../ui/primitives.jsx';

export default function AdminSectionNav({ sections, current, onChange }) {
  return (
    <nav className="admin-section-nav" aria-label="Admin sections">
      {sections.map((section) => (
        <button
          key={section.id}
          type="button"
          className={current === section.id ? 'admin-section-tab active' : 'admin-section-tab'}
          onClick={() => onChange(section.id)}
        >
          <div>
            <strong>{section.label}</strong>
            {section.hint ? <span>{section.hint}</span> : null}
          </div>
          {section.badge ? <StatusBadge tone={section.badgeTone || 'ok'}>{section.badge}</StatusBadge> : null}
        </button>
      ))}
    </nav>
  );
}

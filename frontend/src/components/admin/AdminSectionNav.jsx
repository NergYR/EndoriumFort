import React from 'react';
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
          <div className="admin-section-tab-copy">
            <strong>{section.label}</strong>
            {section.hint ? <span>{section.hint}</span> : null}
          </div>
        </button>
      ))}
    </nav>
  );
}

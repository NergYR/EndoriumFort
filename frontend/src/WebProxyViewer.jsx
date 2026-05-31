import React, { useEffect, useState } from 'react';
import './webproxy.css';
import { useI18n } from './i18n.jsx';

export default function WebProxyViewer({ resourceId, token, resourceName, onNavigate }) {
  const [loading, setLoading] = useState(true);
  const { t } = useI18n();

  useEffect(() => {
    if (!resourceId || !token) {
      onNavigate('/');
      return;
    }
    // Simulate load completion for UI purposes
    const timer = setTimeout(() => setLoading(false), 500);
    return () => clearTimeout(timer);
  }, [resourceId, token, onNavigate]);

  // Use relative proxy URL (cookie-based auth, no token in URL)
  const iframeUrl = `/proxy/${resourceId}/`;
  const backendProxyUrl = `/proxy/${resourceId}/`;

  const openInNewTab = () => {
    window.open(backendProxyUrl, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="web-proxy-container">
      <div className="web-proxy-header">
        <button 
          className="back-button"
          onClick={() => onNavigate('/')}
          title={t('webproxy.dashboard')}
        >
          ← {t('webproxy.back')}
        </button>
        <h2>{resourceName || t('webproxy.resourceTitle', { id: resourceId })}</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <p className="proxy-info">{t('webproxy.secureAccess')}</p>
          <button 
            className="ghost"
            onClick={openInNewTab}
            title={t('webproxy.newTabTitle')}
            style={{ fontSize: '0.9rem', padding: '0.4rem 0.8rem' }}
          >
            ↗ {t('webproxy.newTab')}
          </button>
        </div>
      </div>
      
      <div className="web-proxy-content">
        {loading && (
          <div className="proxy-loading">
            <div className="spinner"></div>
            <p>{t('webproxy.loading')}</p>
          </div>
        )}
        <iframe
          src={iframeUrl}
          title={t('webproxy.iframeTitle', { name: resourceName || t('webproxy.resourceTitle', { id: resourceId }) })}
          className="proxy-iframe"
          onLoad={() => setLoading(false)}
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-top-navigation-by-user-activation"
        />
      </div>
    </div>
  );
}

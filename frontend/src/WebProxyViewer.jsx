import React, { useEffect, useState } from 'react';
import './webproxy.css';

export default function WebProxyViewer({ resourceId, token, resourceName, onNavigate }) {
  const [loading, setLoading] = useState(true);

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
          title="Retour au tableau de bord"
        >
          ← Retour
        </button>
        <h2>{resourceName || `Ressource #${resourceId}`}</h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <p className="proxy-info">Accès sécurisé via le bastion</p>
          <button 
            className="ghost"
            onClick={openInNewTab}
            title="Ouvrir dans un nouvel onglet pour l'authentification HTTP"
            style={{ fontSize: '0.9rem', padding: '0.4rem 0.8rem' }}
          >
            ↗ Nouvel onglet
          </button>
        </div>
      </div>
      
      <div className="web-proxy-content">
        {loading && (
          <div className="proxy-loading">
            <div className="spinner"></div>
            <p>Chargement du contenu...</p>
          </div>
        )}
        <iframe
          src={iframeUrl}
          title={`Proxy pour ${resourceName}`}
          className="proxy-iframe"
          onLoad={() => setLoading(false)}
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-top-navigation-by-user-activation"
        />
      </div>
    </div>
  );
}

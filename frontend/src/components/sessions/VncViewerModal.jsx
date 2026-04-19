import React, { useEffect, useMemo, useRef, useState } from 'react';
import RFB from '@novnc/novnc/core/rfb';
import { useI18n } from '../../i18n.jsx';

function buildVncWebSocketUrl(sessionId) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = new URL('/api/ws/vnc', window.location.origin);
  url.protocol = protocol;
  url.searchParams.set('sessionId', String(sessionId));
  return url.toString();
}

export default function VncViewerModal({ session, onClose }) {
  const { t } = useI18n();
  const canvasRef = useRef(null);
  const rfbRef = useRef(null);
  const [status, setStatus] = useState('connecting');
  const [statusMessage, setStatusMessage] = useState('');

  const wsUrl = useMemo(() => {
    if (!session?.id) return '';
    return buildVncWebSocketUrl(session.id);
  }, [session?.id]);

  useEffect(() => {
    if (!session?.id || !canvasRef.current || !wsUrl) return undefined;

    setStatus('connecting');
    setStatusMessage(t('app.vncLaunching'));

    const rfb = new RFB(canvasRef.current, wsUrl, {
      shared: true,
      credentials: {}
    });
    rfb.scaleViewport = true;
    rfb.resizeSession = true;
    rfb.qualityLevel = 6;
    rfb.compressionLevel = 2;
    rfb.focusOnClick = true;
    rfb.clipViewport = false;
    rfbRef.current = rfb;

    const onConnect = () => {
      setStatus('connected');
      setStatusMessage('');
    };

    const onDisconnect = (event) => {
      const clean = !!event?.detail?.clean;
      setStatus(clean ? 'disconnected' : 'error');
      setStatusMessage(
        clean ? t('app.vncDisconnectedClean') : t('app.vncDisconnectedUnclean')
      );
    };

    const onSecurityFailure = () => {
      setStatus('error');
      setStatusMessage(t('app.vncSecurityFailure'));
    };

    const onCredentialsRequired = () => {
      setStatus('error');
      setStatusMessage(t('app.vncCredentialsRequired'));
    };

    rfb.addEventListener('connect', onConnect);
    rfb.addEventListener('disconnect', onDisconnect);
    rfb.addEventListener('securityfailure', onSecurityFailure);
    rfb.addEventListener('credentialsrequired', onCredentialsRequired);

    return () => {
      rfb.removeEventListener('connect', onConnect);
      rfb.removeEventListener('disconnect', onDisconnect);
      rfb.removeEventListener('securityfailure', onSecurityFailure);
      rfb.removeEventListener('credentialsrequired', onCredentialsRequired);
      try {
        rfb.disconnect();
      } catch (_) {
      }
      rfbRef.current = null;
    };
  }, [session?.id, t, wsUrl]);

  const statusLabel =
    status === 'connected'
      ? t('app.vncStatusConnected')
      : status === 'disconnected'
      ? t('app.vncStatusDisconnected')
      : status === 'error'
      ? t('app.vncStatusError')
      : t('app.vncStatusConnecting');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content vnc-modal" onClick={(event) => event.stopPropagation()}>
        <div className="vnc-modal-header">
          <div>
            <h3>{t('app.vncViewer')}</h3>
            <p className="muted">
              {session?.target}:{session?.port} - session #{session?.id}
            </p>
          </div>
          <div className="vnc-header-actions">
            <span className={`pill ${status === 'connected' ? 'ok' : status === 'connecting' ? 'loading' : 'offline'}`}>
              {statusLabel}
            </span>
            <button type="button" className="ghost" onClick={onClose}>
              {t('common.close')}
            </button>
          </div>
        </div>

        {statusMessage ? <p className="muted vnc-status-message">{statusMessage}</p> : null}

        <div className="vnc-canvas-shell">
          <div ref={canvasRef} className="vnc-canvas" />
        </div>
      </div>
    </div>
  );
}

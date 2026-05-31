import React from 'react';
import { EmptyState, SectionCard, StatusBadge } from '../ui/primitives.jsx';
import { useI18n } from '../../i18n.jsx';

export default function RecordingsPanel({
  loadingRecordings,
  recordings,
  recordingsError,
  loadRecordings,
  closePlayer,
  castData,
  castRecordingId,
  playerPlaying,
  startPlayer,
  stopPlayer,
  playerIndex,
  playerEvents,
  playerTermRef,
  onPlayRecording
}) {
  const { t } = useI18n();

  return (
    <SectionCard
      title={t('recordings.title')}
      subtitle={t('recordings.subtitle')}
      actions={
        <div className="status-row">
          {loadingRecordings ? (
            <StatusBadge tone="loading">{t('common.loading')}</StatusBadge>
          ) : (
            <StatusBadge tone="ok">{t('recordings.recordingsCount', { count: recordings.length })}</StatusBadge>
          )}
        </div>
      }
      className="recordings-panel"
    >
      <div className="audit-controls">
        <button type="button" className="secondary" onClick={() => loadRecordings()} disabled={loadingRecordings}>
          {t('common.refresh')}
        </button>
        <button type="button" className="ghost" onClick={closePlayer}>{t('recordings.resetPlayer')}</button>
      </div>
      {recordingsError && <p className="error">{recordingsError}</p>}
      <div className="audit-list">
        {recordings.length ? (
          recordings.map((rec) => (
            <article className="audit-item" key={rec.id}>
              <div>
                <h4>{t('recordings.recordingLabel', { id: rec.id, sessionId: rec.sessionId })}</h4>
                <p className="muted">
                  {t('recordings.duration', {
                    value: rec.durationMs ? `${(rec.durationMs / 1000).toFixed(1)}s` : t('recordings.inProgress')
                  })} -
                  {t('recordings.size', {
                    value: rec.fileSize ? `${(rec.fileSize / 1024).toFixed(1)} KB` : '-'
                  })}
                </p>
              </div>
              <div className="audit-meta">
                <span className="muted">{rec.createdAt}</span>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => onPlayRecording(rec.id)}
                >
                  {castRecordingId === rec.id ? t('recordings.playing') : t('recordings.play')}
                </button>
              </div>
            </article>
          ))
        ) : (
          <EmptyState title={t('recordings.emptyTitle')} message={t('recordings.emptyMessage')} />
        )}
      </div>
      {castData && (
        <div className="recording-player-card">
          <div className="recording-player-header">
            <h4 className="recording-player-title">{t('recordings.replayTitle', { id: castRecordingId })}</h4>
            <div className="recording-player-actions">
              {!playerPlaying ? (
                <button
                  type="button"
                  className="secondary recording-player-btn"
                  onClick={startPlayer}
                >
                  {t('recordings.play')}
                </button>
              ) : (
                <button
                  type="button"
                  className="secondary recording-player-btn"
                  onClick={stopPlayer}
                >
                  {t('recordings.pause')}
                </button>
              )}
              <span className="recording-player-meta">
                {t('recordings.eventsCount', { index: playerIndex, total: playerEvents.length })}
              </span>
              <button
                type="button"
                className="ghost recording-player-close"
                onClick={closePlayer}
              >
                {t('common.close')}
              </button>
            </div>
          </div>
          <div
            className="terminal-shell"
            ref={playerTermRef}
            style={{ minHeight: '240px', borderRadius: '6px' }}
          />
          <p className="recording-player-note">
            {t('recordings.animatedReplay')}
          </p>
        </div>
      )}
    </SectionCard>
  );
}

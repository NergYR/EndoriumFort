import React from 'react';
import { EmptyState, SectionCard, StatusBadge } from '../ui/primitives.jsx';

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
  return (
    <SectionCard
      title="Session Recordings"
      subtitle="Replay SSH sessions and inspect recorded evidence."
      actions={
        <div className="status-row">
          {loadingRecordings ? (
            <StatusBadge tone="loading">loading</StatusBadge>
          ) : (
            <StatusBadge tone="ok">{recordings.length} recordings</StatusBadge>
          )}
        </div>
      }
      className="recordings-panel"
    >
      <div className="audit-controls">
        <button type="button" className="secondary" onClick={() => loadRecordings()} disabled={loadingRecordings}>
          Refresh
        </button>
        <button type="button" className="ghost" onClick={closePlayer}>Reset player</button>
      </div>
      {recordingsError && <p className="error">{recordingsError}</p>}
      <div className="audit-list">
        {recordings.length ? (
          recordings.map((rec) => (
            <article className="audit-item" key={rec.id}>
              <div>
                <h4>Recording #{rec.id} - Session #{rec.sessionId}</h4>
                <p className="muted">
                  Duration: {rec.durationMs ? `${(rec.durationMs / 1000).toFixed(1)}s` : 'in progress'} -
                  Size: {rec.fileSize ? `${(rec.fileSize / 1024).toFixed(1)} KB` : '-'}
                </p>
              </div>
              <div className="audit-meta">
                <span className="muted">{rec.createdAt}</span>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => onPlayRecording(rec.id)}
                >
                  {castRecordingId === rec.id ? 'Playing' : 'Play'}
                </button>
              </div>
            </article>
          ))
        ) : (
          <EmptyState title="No recordings available" message="Replay data will appear here after SSH sessions are captured." />
        )}
      </div>
      {castData && (
        <div className="recording-player-card">
          <div className="recording-player-header">
            <h4 className="recording-player-title">Replay - Recording #{castRecordingId}</h4>
            <div className="recording-player-actions">
              {!playerPlaying ? (
                <button
                  type="button"
                  className="secondary recording-player-btn"
                  onClick={startPlayer}
                >
                  Play
                </button>
              ) : (
                <button
                  type="button"
                  className="secondary recording-player-btn"
                  onClick={stopPlayer}
                >
                  Pause
                </button>
              )}
              <span className="recording-player-meta">
                {playerIndex}/{playerEvents.length} events
              </span>
              <button
                type="button"
                className="ghost recording-player-close"
                onClick={closePlayer}
              >
                Close
              </button>
            </div>
          </div>
          <div
            className="terminal-shell"
            ref={playerTermRef}
            style={{ minHeight: '240px', borderRadius: '6px' }}
          />
          <p className="recording-player-note">
            Animated replay powered by xterm.js.
          </p>
        </div>
      )}
    </SectionCard>
  );
}

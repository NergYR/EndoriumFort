import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import {
  createSession,
  fetchHealth,
  fetchSessions,
  login,
  setAuthToken,
  terminateSession
} from './api.js';

const protocolList = [
  { name: 'SSH', detail: 'Low-latency shell access', status: 'ready' },
  { name: 'RDP', detail: 'Windows desktops and apps', status: 'ready' },
  { name: 'VNC', detail: 'Legacy console access', status: 'monitor' },
  { name: 'HTTP', detail: 'Web admin panels', status: 'ready' }
];

const alertStream = [
  {
    title: 'Suspicious login attempt blocked',
    detail: 'Geo-anomaly detected for user ops-admin',
    level: 'critical'
  },
  {
    title: 'Privileged session elevated',
    detail: 'Finance-ERP SSH session now under recording',
    level: 'warning'
  },
  {
    title: 'Audit export completed',
    detail: 'Session bundle ready for compliance review',
    level: 'ok'
  }
];

const integrationList = [
  { name: 'SAML / OIDC', detail: 'Central identity provider' },
  { name: 'LDAP / AD', detail: 'Directory sync and RBAC' },
  { name: 'SIEM', detail: 'Push audit events in real time' },
  { name: 'Ticketing', detail: 'Just-in-time approvals' }
];

export default function App() {
  const [status, setStatus] = useState('loading');
  const [detail, setDetail] = useState('');
  const [auth, setAuth] = useState({
    user: '',
    role: 'operator',
    token: ''
  });
  const [authError, setAuthError] = useState('');
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [form, setForm] = useState({
    target: '10.0.0.12',
    user: 'ops-admin',
    protocol: 'ssh',
    port: '22'
  });
  const [activeTerminalSession, setActiveTerminalSession] = useState(null);
  const [terminalStatus, setTerminalStatus] = useState('idle');
  const [terminalError, setTerminalError] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const terminalRef = useRef(null);
  const terminalInstanceRef = useRef(null);
  const fitAddonRef = useRef(null);
  const socketRef = useRef(null);

  useEffect(() => {
    let active = true;
    fetchHealth()
      .then((data) => {
        if (!active) return;
        setStatus(data.status || 'ok');
        setDetail(data.message || 'API reachable');
      })
      .catch(() => {
        if (!active) return;
        setStatus('offline');
        setDetail('Start the backend to enable health checks.');
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!auth.token) {
      setSessions([]);
      setLoadingSessions(false);
      return;
    }
    let active = true;
    setLoadingSessions(true);
    fetchSessions()
      .then((data) => {
        if (!active) return;
        setSessions(Array.isArray(data.items) ? data.items : []);
        setSessionError('');
      })
      .catch((error) => {
        if (!active) return;
        setSessionError(error.message || 'Unable to load sessions');
      })
      .finally(() => {
        if (!active) return;
        setLoadingSessions(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  const onFieldChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const onAuthChange = (event) => {
    const { name, value } = event.target;
    setAuth((prev) => ({ ...prev, [name]: value }));
  };

  const onLogin = async (event) => {
    event.preventDefault();
    try {
      const payload = await login({ user: auth.user, role: auth.role });
      setAuth((prev) => ({ ...prev, token: payload.token }));
      setForm((prev) => ({ ...prev, user: payload.user }));
      setAuthToken(payload.token);
      setAuthError('');
    } catch (error) {
      setAuthError(error.message || 'Login failed');
    }
  };

  const onLogout = () => {
    setAuth((prev) => ({ ...prev, token: '' }));
    setAuthToken('');
  };

  const onCreateSession = async (event) => {
    event.preventDefault();
    try {
      const payload = {
        ...form,
        port: Number.parseInt(form.port, 10) || 22
      };
      const created = await createSession(payload);
      setSessions((prev) => [created, ...prev]);
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to create session');
    }
  };

  const onTerminate = async (sessionId) => {
    try {
      const updated = await terminateSession(sessionId);
      setSessions((prev) =>
        prev.map((item) => (item.id === sessionId ? updated : item))
      );
    } catch (error) {
      setSessionError(error.message || 'Unable to terminate session');
    }
  };

  useEffect(() => {
    if (!activeTerminalSession || !terminalRef.current) {
      return undefined;
    }

    const terminal = new Terminal({
      fontFamily: '"IBM Plex Mono", "Fira Code", monospace',
      fontSize: 13,
      cursorBlink: true,
      theme: {
        background: '#111827',
        foreground: '#f9fafb',
        cursor: '#f59e0b'
      }
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalRef.current);
    fitAddon.fit();

    terminalInstanceRef.current = terminal;
    fitAddonRef.current = fitAddon;

    const handleResize = () => {
      if (!fitAddonRef.current || !terminalInstanceRef.current) {
        return;
      }
      fitAddonRef.current.fit();
      if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
        socketRef.current.send(
          JSON.stringify({
            type: 'resize',
            cols: terminalInstanceRef.current.cols,
            rows: terminalInstanceRef.current.rows
          })
        );
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
      terminal.dispose();
      terminalInstanceRef.current = null;
      fitAddonRef.current = null;
    };
  }, [activeTerminalSession]);

  const openTerminal = (session) => {
    setActiveTerminalSession(session);
    setSshPassword('');
    setTerminalError('');
    setTerminalStatus('idle');
  };

  const connectTerminal = () => {
    if (!activeTerminalSession) {
      setTerminalError('Pick a session to connect.');
      return;
    }
    if (!sshPassword) {
      setTerminalError('SSH password is required.');
      return;
    }
    if (!auth.token) {
      setTerminalError('Sign in first.');
      return;
    }

    const terminal = terminalInstanceRef.current;
    if (!terminal) {
      setTerminalError('Terminal not ready.');
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${protocol}://${window.location.host}/api/ws/ssh?token=${encodeURIComponent(
      auth.token
    )}`;
    const socket = new WebSocket(wsUrl);
    socket.binaryType = 'arraybuffer';
    socketRef.current = socket;
    setTerminalStatus('connecting');

    socket.addEventListener('open', () => {
      setTerminalStatus('live');
      terminal.focus();
      socket.send(
        JSON.stringify({
          type: 'start',
          sessionId: activeTerminalSession.id,
          password: sshPassword,
          cols: terminal.cols,
          rows: terminal.rows
        })
      );
      terminal.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'input', data }));
        }
      });
    });

    socket.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'error') {
            setTerminalError(payload.message || 'SSH error');
          }
        } catch (error) {
          terminal.write(event.data);
        }
        return;
      }
      const decoder = new TextDecoder();
      terminal.write(decoder.decode(event.data));
    });

    socket.addEventListener('close', () => {
      setTerminalStatus('closed');
    });

    socket.addEventListener('error', () => {
      setTerminalStatus('error');
      setTerminalError('WebSocket error.');
    });
  };

  const activeSessions = useMemo(
    () => sessions.filter((session) => session.status === 'active'),
    [sessions]
  );
  const terminatedSessions = useMemo(
    () => sessions.filter((session) => session.status !== 'active'),
    [sessions]
  );
  const lastSession = useMemo(() => {
    if (!sessions.length) return null;
    return [...sessions].sort((a, b) => b.id - a.id)[0];
  }, [sessions]);

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">
          <span className="badge">EndoriumFort</span>
          <div>
            <h1>WebBastion Control Plane</h1>
            <p>Agentless access with traceable, policy-driven sessions.</p>
          </div>
        </div>
        <div className="top-actions">
          <div className="health">
            <span className={`pill ${status}`}>{status}</span>
            <span className="detail">{detail}</span>
          </div>
          <button type="button" className="ghost">
            Open policy vault
          </button>
        </div>
      </header>

      <section className="hero-grid">
        <div className="hero-card reveal">
          <h2>Centralized command</h2>
          <p className="lead">
            Orchestrate SSH, RDP, and VNC access with live oversight, privileged
            elevation, and a replay-ready audit trail.
          </p>
          <div className="hero-tags">
            <span className="tag">MFA enforced</span>
            <span className="tag">Just-in-time access</span>
            <span className="tag">Session recording</span>
          </div>
        </div>
        <div className="kpi-grid">
          <article className="kpi-card reveal delay-1">
            <h3>Active sessions</h3>
            <p className="kpi-value">{activeSessions.length}</p>
            <span className="muted">Live supervision</span>
          </article>
          <article className="kpi-card reveal delay-2">
            <h3>Recent connections</h3>
            <p className="kpi-value">{sessions.length}</p>
            <span className="muted">Last 24h window</span>
          </article>
          <article className="kpi-card reveal delay-3">
            <h3>Alerts</h3>
            <p className="kpi-value">{alertStream.length}</p>
            <span className="muted">Risk-based triggers</span>
          </article>
          <article className="kpi-card reveal delay-4">
            <h3>Audit queue</h3>
            <p className="kpi-value">{terminatedSessions.length}</p>
            <span className="muted">Sessions to review</span>
          </article>
        </div>
      </section>

      <section className="main-grid">
        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Session management</h3>
              <p>Start, supervise, and terminate remote access in real time.</p>
            </div>
            <div className="status-row">
              {auth.token ? (
                loadingSessions ? (
                  <span className="pill loading">loading</span>
                ) : (
                  <span className="pill ok">{activeSessions.length} active</span>
                )
              ) : (
                <span className="pill loading">waiting auth</span>
              )}
            </div>
          </div>

          <div className="auth-panel">
            <form className="auth-form" onSubmit={onLogin}>
              <label>
                User
                <input
                  name="user"
                  value={auth.user}
                  onChange={onAuthChange}
                  placeholder="ops-admin"
                  disabled={!!auth.token}
                />
              </label>
              <label>
                Role
                <select
                  name="role"
                  value={auth.role}
                  onChange={onAuthChange}
                  disabled={!!auth.token}
                >
                  <option value="operator">operator</option>
                  <option value="admin">admin</option>
                  <option value="auditor">auditor</option>
                </select>
              </label>
              <button type="submit" disabled={!!auth.token}>
                Sign in
              </button>
              {auth.token && (
                <button type="button" className="secondary" onClick={onLogout}>
                  Sign out
                </button>
              )}
            </form>
            {auth.token && (
              <div className="auth-meta">
                <span className="pill ok">{auth.role}</span>
                <span className="muted">Token issued</span>
              </div>
            )}
            {authError && <p className="error">{authError}</p>}
          </div>

          <form className="session-form" onSubmit={onCreateSession}>
            <label>
              Target
              <input name="target" value={form.target} onChange={onFieldChange} />
            </label>
            <label>
              Port
              <input
                name="port"
                type="number"
                min="1"
                max="65535"
                value={form.port}
                onChange={onFieldChange}
              />
            </label>
            <label>
              User
              <input name="user" value={form.user} onChange={onFieldChange} />
            </label>
            <label>
              Protocol
              <select
                name="protocol"
                value={form.protocol}
                onChange={onFieldChange}
              >
                <option value="ssh">ssh</option>
                <option value="rdp">rdp</option>
                <option value="vnc">vnc</option>
                <option value="http">http</option>
              </select>
            </label>
            <button type="submit" disabled={!auth.token}>
              Create session
            </button>
          </form>

          {sessionError && <p className="error">{sessionError}</p>}

          {auth.token ? (
            <div className="session-grid">
              {sessions.map((session) => (
                <article className="session-card" key={session.id}>
                  <header>
                    <div>
                      <h4>#{session.id}</h4>
                      <span className="muted">
                        {session.protocol} : {session.port}
                      </span>
                    </div>
                    <span className={`pill ${session.status}`}>
                      {session.status}
                    </span>
                  </header>
                  <p className="session-route">
                    <strong>{session.user}</strong>
                    <span className="arrow">to</span>
                    <strong>{session.target}</strong>
                  </p>
                  <div className="session-meta">
                    <span>Opened: {session.createdAt}</span>
                    {session.terminatedAt && (
                      <span>Closed: {session.terminatedAt}</span>
                    )}
                  </div>
                  <div className="session-actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => onTerminate(session.id)}
                      disabled={session.status !== 'active'}
                    >
                      Terminate
                    </button>
                    <button type="button" className="ghost">
                      Open audit
                    </button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => openTerminal(session)}
                      disabled={session.status !== 'active'}
                    >
                      Open live
                    </button>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <p className="muted">Sign in to view and manage sessions.</p>
          )}
        </div>

        <aside className="side-stack">
          <div className="panel compact reveal">
            <div className="panel-header">
              <div>
                <h3>Access control</h3>
                <p>Role-based guards and approval trails.</p>
              </div>
            </div>
            <ul className="list">
              <li>
                <span>Operator</span>
                <span className="muted">Limited to pre-approved targets</span>
              </li>
              <li>
                <span>Admin</span>
                <span className="muted">Can elevate and approve access</span>
              </li>
              <li>
                <span>Auditor</span>
                <span className="muted">Read-only audit & replay access</span>
              </li>
            </ul>
            <div className="panel-footer">
              <span className="tag">Policy version 4.2</span>
              <span className="tag">JIT approvals</span>
            </div>
          </div>

          <div className="panel compact reveal">
            <div className="panel-header">
              <div>
                <h3>Recording & audit</h3>
                <p>Session capture with replay and export.</p>
              </div>
            </div>
            <div className="audit-timeline">
              <div>
                <span className="pill ok">last session</span>
                <p>{lastSession ? `#${lastSession.id}` : 'Awaiting activity'}</p>
              </div>
              <div>
                <span className="pill loading">capture</span>
                <p>Keystroke + video stream</p>
              </div>
              <div>
                <span className="pill offline">export</span>
                <p>PDF summary, JSON log</p>
              </div>
            </div>
          </div>

          <div className="panel compact reveal">
            <div className="panel-header">
              <div>
                <h3>Identity & integrations</h3>
                <p>Connect external auth and compliance systems.</p>
              </div>
            </div>
            <ul className="list">
              {integrationList.map((item) => (
                <li key={item.name}>
                  <span>{item.name}</span>
                  <span className="muted">{item.detail}</span>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </section>

      <section className="wide-panels">
        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Notifications & alerts</h3>
              <p>Live signals for risk and operational events.</p>
            </div>
            <button type="button" className="secondary">
              Open alert feed
            </button>
          </div>
          <div className="alert-grid">
            {alertStream.map((alert) => (
              <article className={`alert-card ${alert.level}`} key={alert.title}>
                <h4>{alert.title}</h4>
                <p className="muted">{alert.detail}</p>
              </article>
            ))}
          </div>
        </div>

        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Protocol hub</h3>
              <p>Unified gateway for SSH, RDP, VNC, and web access.</p>
            </div>
            <button type="button" className="secondary">
              Manage connectors
            </button>
          </div>
          <div className="protocol-grid">
            {protocolList.map((protocol) => (
              <article className="protocol-card" key={protocol.name}>
                <div>
                  <h4>{protocol.name}</h4>
                  <p className="muted">{protocol.detail}</p>
                </div>
                <span className={`pill ${protocol.status}`}>
                  {protocol.status}
                </span>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="panel personalization reveal">
        <div className="panel-header">
          <div>
            <h3>Personalization</h3>
            <p>Shape the console for each security team.</p>
          </div>
          <button type="button" className="ghost">
            Save layout
          </button>
        </div>
        <div className="personalization-grid">
          <div>
            <span className="muted">Theme</span>
            <h4>Sandstone</h4>
          </div>
          <div>
            <span className="muted">Default view</span>
            <h4>Session dashboard</h4>
          </div>
          <div>
            <span className="muted">Widgets</span>
            <h4>12 active</h4>
          </div>
          <div>
            <span className="muted">Notifications</span>
            <h4>Risk-based only</h4>
          </div>
        </div>
      </section>

      <section className="panel terminal-panel reveal">
        <div className="panel-header">
          <div>
            <h3>Live SSH console</h3>
            <p>Connect to the selected session with on-demand credentials.</p>
          </div>
          <span className={`pill ${terminalStatus === 'live' ? 'ok' : 'loading'}`}>
            {terminalStatus}
          </span>
        </div>
        <div className="terminal-controls">
          <div>
            <span className="muted">Session</span>
            <h4>
              {activeTerminalSession
                ? `#${activeTerminalSession.id} ${activeTerminalSession.target}`
                : 'No session selected'}
            </h4>
          </div>
          <label>
            SSH password
            <input
              type="password"
              value={sshPassword}
              onChange={(event) => setSshPassword(event.target.value)}
              placeholder="Enter SSH password"
            />
          </label>
          <button type="button" onClick={connectTerminal}>
            Connect
          </button>
        </div>
        {terminalError && <p className="error">{terminalError}</p>}
        <div className="terminal-shell" ref={terminalRef} />
      </section>
    </div>
  );
}

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import WebProxyViewer from './WebProxyViewer.jsx';
import {
  changePassword,
  createResource,
  createSession,
  deleteResource,
  deleteUser,
  disable2FA,
  fetchAudit,
  fetchHealth,
  fetchRecordingCast,
  fetchRecordings,
  fetchResourceCredentials,
  fetchResources,
  fetchSessions,
  fetchStats,
  fetchUsers,
  get2FAStatus,
  login,
  logout,
  setAuthToken,
  setup2FA,
  terminateSession,
  updateResource,
  updateUser,
  createUser,
  getUserResourcePermissions,
  grantResourcePermission,
  revokeResourcePermission,
  verify2FA
} from './api.js';

export default function App() {
  const [status, setStatus] = useState('loading');
  const [detail, setDetail] = useState('');
  const [auth, setAuth] = useState(() => {
    try {
      const saved = localStorage.getItem('endoriumfort_auth');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.token) {
          setAuthToken(parsed.token);
          return { user: parsed.user || '', password: '', role: parsed.role || 'operator', token: parsed.token };
        }
      }
    } catch (_) {}
    return { user: '', password: '', role: 'operator', token: '' };
  });
  const [authError, setAuthError] = useState('');
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [activeTerminalSession, setActiveTerminalSession] = useState(null);
  const [terminalStatus, setTerminalStatus] = useState('idle');
  const [terminalError, setTerminalError] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [auditOpen, setAuditOpen] = useState(false);
  const [auditItems, setAuditItems] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [auditFilter, setAuditFilter] = useState(null);
  const [resources, setResources] = useState([]);
  const [loadingResources, setLoadingResources] = useState(false);
  const [resourceError, setResourceError] = useState('');
  const [resourceForm, setResourceForm] = useState({
    name: '',
    target: '',
    protocol: 'ssh',
    port: '22',
    description: '',
    imageUrl: '',
    httpUsername: '',
    httpPassword: '',
    sshUsername: '',
    sshPassword: ''
  });
  const [editingResourceId, setEditingResourceId] = useState(null);
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [userError, setUserError] = useState('');
  const [userForm, setUserForm] = useState({
    username: '',
    password: '',
    role: 'operator'
  });
  const [editingUserId, setEditingUserId] = useState(null);
  const [selectedUserForPermissions, setSelectedUserForPermissions] = useState(null);
  const [userPermissions, setUserPermissions] = useState([]);
  const [loadingPermissions, setLoadingPermissions] = useState(false);
  const [permissionsError, setPermissionsError] = useState('');
  const [webProxyResourceId, setWebProxyResourceId] = useState(null);
  const [webProxyToken, setWebProxyToken] = useState(null);
  const [webProxyResourceName, setWebProxyResourceName] = useState('');
  const [route, setRoute] = useState(() =>
    window.location.pathname ? window.location.pathname : '/'
  );
  // 2FA state
  const [twoFARequired, setTwoFARequired] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState(null);
  const [totpSetupCode, setTotpSetupCode] = useState('');
  const [totpError, setTotpError] = useState('');
  const [totpDisableCode, setTotpDisableCode] = useState('');
  // Recordings state
  const [recordings, setRecordings] = useState([]);
  const [loadingRecordings, setLoadingRecordings] = useState(false);
  const [recordingsError, setRecordingsError] = useState('');
  const [recordingsOpen, setRecordingsOpen] = useState(false);
  const [castData, setCastData] = useState(null);
  const [castRecordingId, setCastRecordingId] = useState(null);
  // Dashboard stats
  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(false);
  // Audit search
  const [auditSearchQuery, setAuditSearchQuery] = useState('');
  const [auditTypeFilter, setAuditTypeFilter] = useState('');
  // Animated player
  const [playerEvents, setPlayerEvents] = useState([]);
  const [playerIndex, setPlayerIndex] = useState(0);
  const [playerPlaying, setPlayerPlaying] = useState(false);
  const playerTermRef = useRef(null);
  const playerTermInstanceRef = useRef(null);
  const playerFitRef = useRef(null);
  const playerTimerRef = useRef(null);
  // Shadow session (admin live monitoring)
  const [shadowSession, setShadowSession] = useState(null);
  const [shadowStatus, setShadowStatus] = useState('idle');
  const shadowTermRef = useRef(null);
  const shadowTermInstanceRef = useRef(null);
  const shadowFitRef = useRef(null);
  const shadowSocketRef = useRef(null);
  // Agent launch modal
  const [agentModal, setAgentModal] = useState(null); // { resource, port, command, copied }
  // Dark mode
  const [darkMode, setDarkMode] = useState(() => {
    try { return localStorage.getItem('endoriumfort_darkmode') === 'true'; } catch (_) { return false; }
  });
  // Change password
  const [changePwOpen, setChangePwOpen] = useState(false);
  const [changePwCurrent, setChangePwCurrent] = useState('');
  const [changePwNew, setChangePwNew] = useState('');
  const [changePwConfirm, setChangePwConfirm] = useState('');
  const [changePwError, setChangePwError] = useState('');
  const [changePwSuccess, setChangePwSuccess] = useState('');
  // Token expiry
  const [tokenExpiresAt, setTokenExpiresAt] = useState('');
  const terminalRef = useRef(null);
  const terminalInstanceRef = useRef(null);
  const fitAddonRef = useRef(null);
  const socketRef = useRef(null);

  const navigate = (path) => {
    if (window.location.pathname !== path) {
      window.history.pushState({}, '', path);
      setRoute(path);
    }
  };

  useEffect(() => {
    const handlePopState = () => {
      setRoute(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Dark mode effect
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('endoriumfort_darkmode', darkMode ? 'true' : 'false');
  }, [darkMode]);

  // Token expiry auto-logout
  useEffect(() => {
    if (!tokenExpiresAt || !auth.token) return;
    const remaining = new Date(tokenExpiresAt).getTime() - Date.now();
    if (remaining <= 0) {
      onLogout();
      return;
    }
    const timer = setTimeout(() => {
      onLogout();
      setAuthError('Session expired. Please login again.');
    }, remaining);
    return () => clearTimeout(timer);
  }, [tokenExpiresAt, auth.token]);

  useEffect(() => {
    if (!auth.token && route !== '/login') {
      navigate('/login');
    }
    if (auth.token && route === '/login') {
      navigate('/');
    }
  }, [auth.token, route]);

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

  useEffect(() => {
    if (!auth.token) {
      setResources([]);
      setLoadingResources(false);
      return;
    }
    let active = true;
    setLoadingResources(true);
    fetchResources()
      .then((data) => {
        if (!active) return;
        setResources(Array.isArray(data.items) ? data.items : []);
        setResourceError('');
      })
      .catch((error) => {
        if (!active) return;
        setResourceError(error.message || 'Unable to load resources');
      })
      .finally(() => {
        if (!active) return;
        setLoadingResources(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token || auth.role !== 'admin') {
      setUsers([]);
      setLoadingUsers(false);
      return;
    }
    let active = true;
    setLoadingUsers(true);
    fetchUsers()
      .then((data) => {
        if (!active) return;
        setUsers(Array.isArray(data.items) ? data.items : []);
        setUserError('');
      })
      .catch((error) => {
        if (!active) return;
        setUserError(error.message || 'Unable to load users');
      })
      .finally(() => {
        if (!active) return;
        setLoadingUsers(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, auth.role]);

  // Fetch dashboard stats periodically
  useEffect(() => {
    if (!auth.token) { setStats(null); return; }
    let active = true;
    const load = () => {
      setLoadingStats(true);
      fetchStats()
        .then((data) => { if (active) setStats(data); })
        .catch(() => {})
        .finally(() => { if (active) setLoadingStats(false); });
    };
    load();
    const interval = setInterval(load, 15000); // refresh every 15s
    return () => { active = false; clearInterval(interval); };
  }, [auth.token]);

  const onAuthChange = (event) => {
    const { name, value } = event.target;
    setAuth((prev) => ({ ...prev, [name]: value }));
  };

  const onResourceFieldChange = (event) => {
    const { name, value } = event.target;
    setResourceForm((prev) => ({ ...prev, [name]: value }));
  };

  const onUserFieldChange = (event) => {
    const { name, value } = event.target;
    setUserForm((prev) => ({ ...prev, [name]: value }));
  };

  const onLogin = async (event) => {
    event.preventDefault();
    try {
      const payload = await login({
        user: auth.user,
        password: auth.password,
        totpCode: totpCode || undefined
      });

      // Check if 2FA is required
      if (payload.status === '2fa_required') {
        setTwoFARequired(true);
        setTotpCode('');
        setAuthError('');
        return;
      }

      setTwoFARequired(false);
      setTotpCode('');
      setAuth((prev) => ({
        ...prev,
        token: payload.token,
        role: payload.role,
        user: payload.user,
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: payload.role
      }));
      setAuthError('');
      navigate('/');
    } catch (error) {
      setAuthError(error.message || 'Login failed');
    }
  };

  const onLogout = async () => {
    try { await logout(); } catch (_) {}
    setAuth((prev) => ({ ...prev, token: '', password: '' }));
    setAuthToken('');
    setTokenExpiresAt('');
    localStorage.removeItem('endoriumfort_auth');
    navigate('/login');
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

  const loadAudit = async () => {
    if (!auth.token) {
      setAuditError('Sign in to view audit logs.');
      return;
    }
    setLoadingAudit(true);
    try {
      const data = await fetchAudit();
      setAuditItems(Array.isArray(data.items) ? data.items : []);
      setAuditError('');
    } catch (error) {
      setAuditError(error.message || 'Unable to load audit log');
    } finally {
      setLoadingAudit(false);
    }
  };

  const openAudit = (sessionId = null) => {
    setAuditOpen(true);
    setAuditFilter(sessionId);
    loadAudit();
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

  const onConnectResource = async (resource) => {
    if (!auth.token) {
      setSessionError('Sign in to start a session.');
      return;
    }

    // Handle web resources via proxy
    if (resource.protocol === 'http' || resource.protocol === 'https') {
      setWebProxyResourceId(resource.id);
      setWebProxyToken(auth.token);
      setWebProxyResourceName(resource.name);
      navigate('/webproxy');
      return;
    }

    // Handle agent resources — open agent launch modal with random port
    if (resource.protocol === 'agent') {
      const randomPort = 10000 + Math.floor(Math.random() * 50000);
      const serverUrl = window.location.origin;
      const cmd = `endoriumfort-agent connect --server ${serverUrl} --token ${auth.token} --resource ${resource.id} --local-port ${randomPort}`;
      setAgentModal({ resource, port: randomPort, command: cmd, copied: false });
      return;
    }

    // Handle SSH/other protocols
    try {
      const payload = {
        target: resource.target,
        user: resource.sshUsername || auth.user,
        protocol: resource.protocol,
        port: resource.port
      };
      const created = await createSession(payload);
      setSessions((prev) => [created, ...prev]);
      setSessionError('');
      openTerminal(created);

      // Auto-inject credentials if stored in the vault
      if (resource.hasCredentials) {
        try {
          const creds = await fetchResourceCredentials(resource.id);
          if (creds.sshPassword) {
            setSshPassword(creds.sshPassword);
          }
        } catch (_) {
          // Silently fallback to manual password entry
        }
      }
    } catch (error) {
      setSessionError(error.message || 'Unable to create session');
    }
  };

  const onSubmitResource = async (event) => {
    event.preventDefault();
    setResourceError('');
    const payload = {
      name: resourceForm.name.trim(),
      target: resourceForm.target.trim(),
      protocol: resourceForm.protocol,
      port: Number.parseInt(resourceForm.port, 10) || 22,
      description: resourceForm.description.trim(),
      imageUrl: resourceForm.imageUrl.trim(),
      httpUsername: resourceForm.httpUsername.trim(),
      httpPassword: resourceForm.httpPassword,
      sshUsername: resourceForm.sshUsername.trim(),
      sshPassword: resourceForm.sshPassword
    };
    try {
      if (editingResourceId) {
        const updated = await updateResource(editingResourceId, payload);
        setResources((prev) =>
          prev.map((item) => (item.id === editingResourceId ? updated : item))
        );
      } else {
        const created = await createResource(payload);
        setResources((prev) => [...prev, created]);
      }
      setEditingResourceId(null);
      setResourceForm({
        name: '',
        target: '',
        protocol: 'ssh',
        port: '22',
        description: '',
        imageUrl: '',
        httpUsername: '',
        httpPassword: '',
        sshUsername: '',
        sshPassword: ''
      });
    } catch (error) {
      setResourceError(error.message || 'Unable to save resource');
    }
  };

  const onEditResource = (resource) => {
    setEditingResourceId(resource.id);
    setResourceForm({
      name: resource.name || '',
      target: resource.target || '',
      protocol: resource.protocol || 'ssh',
      port: String(resource.port || 22),
      description: resource.description || '',
      imageUrl: resource.imageUrl || '',
      httpUsername: resource.httpUsername || '',
      httpPassword: '',
      sshUsername: resource.sshUsername || '',
      sshPassword: ''
    });
  };

  const onDeleteResource = async (resourceId) => {
    try {
      await deleteResource(resourceId);
      setResources((prev) => prev.filter((item) => item.id !== resourceId));
    } catch (error) {
      setResourceError(error.message || 'Unable to delete resource');
    }
  };

  const onSubmitUser = async (event) => {
    event.preventDefault();
    setUserError('');
    const payload = {
      username: userForm.username.trim(),
      password: userForm.password,
      role: userForm.role
    };
    try {
      if (editingUserId) {
        const updated = await updateUser(editingUserId, {
          password: payload.password,
          role: payload.role
        });
        setUsers((prev) =>
          prev.map((item) => (item.id === editingUserId ? updated : item))
        );
      } else {
        const created = await createUser(payload);
        setUsers((prev) => [...prev, created]);
      }
      setEditingUserId(null);
      setUserForm({
        username: '',
        password: '',
        role: 'operator'
      });
    } catch (error) {
      setUserError(error.message || 'Unable to save user');
    }
  };

  const onEditUser = (user) => {
    setEditingUserId(user.id);
    setUserForm({
      username: user.username || '',
      password: '',
      role: user.role || 'operator'
    });
  };

  const onDeleteUser = async (userId) => {
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((item) => item.id !== userId));
    } catch (error) {
      setUserError(error.message || 'Unable to delete user');
    }
  };

  const onLoadUserPermissions = async (user) => {
    try {
      setLoadingPermissions(true);
      setSelectedUserForPermissions(user);
      const response = await getUserResourcePermissions(user.id);
      setUserPermissions(response.resourceIds || []);
      setPermissionsError('');
    } catch (error) {
      setPermissionsError(error.message || 'Unable to load permissions');
    } finally {
      setLoadingPermissions(false);
    }
  };

  const onToggleResourcePermission = async (resourceId) => {
    if (!selectedUserForPermissions) return;
    
    const hasPermission = userPermissions.includes(resourceId);
    try {
      if (hasPermission) {
        await revokeResourcePermission(selectedUserForPermissions.id, resourceId);
        setUserPermissions((prev) => prev.filter((id) => id !== resourceId));
      } else {
        await grantResourcePermission(selectedUserForPermissions.id, resourceId);
        setUserPermissions((prev) => [...prev, resourceId]);
      }
      setPermissionsError('');
    } catch (error) {
      setPermissionsError(error.message || 'Unable to modify permission');
    }
  };

  // ── 2FA handlers ──

  const onSetup2FA = async () => {
    setTotpError('');
    try {
      const data = await setup2FA();
      setTotpSetupData(data);
    } catch (error) {
      setTotpError(error.message || 'Failed to setup 2FA');
    }
  };

  const onVerify2FA = async () => {
    setTotpError('');
    try {
      await verify2FA(totpSetupCode);
      setTotpEnabled(true);
      setTotpSetupData(null);
      setTotpSetupCode('');
      setTotpError('');
    } catch (error) {
      setTotpError(error.message || 'Invalid code');
    }
  };

  const onDisable2FA = async () => {
    setTotpError('');
    try {
      await disable2FA(totpDisableCode);
      setTotpEnabled(false);
      setTotpDisableCode('');
      setTotpError('');
    } catch (error) {
      setTotpError(error.message || 'Invalid code');
    }
  };

  const onLoad2FAStatus = async () => {
    try {
      const data = await get2FAStatus();
      setTotpEnabled(!!data.totpEnabled);
    } catch (_) {}
  };

  useEffect(() => {
    if (auth.token) onLoad2FAStatus();
  }, [auth.token]);

  // ── Recording handlers ──

  const loadRecordings = async (sessionId = null) => {
    setLoadingRecordings(true);
    setRecordingsError('');
    try {
      const data = await fetchRecordings(sessionId);
      setRecordings(Array.isArray(data.items) ? data.items : []);
    } catch (error) {
      setRecordingsError(error.message || 'Unable to load recordings');
    } finally {
      setLoadingRecordings(false);
    }
  };

  const openRecordings = (sessionId = null) => {
    setRecordingsOpen(true);
    setCastData(null);
    setCastRecordingId(null);
    loadRecordings(sessionId);
  };

  const onPlayRecording = async (recordingId) => {
    try {
      const data = await fetchRecordingCast(recordingId);
      setCastData(data);
      setCastRecordingId(recordingId);

      // Parse cast events for animated player
      const lines = data.trim().split('\n');
      if (lines.length > 1) {
        const header = JSON.parse(lines[0]);
        const events = [];
        for (let i = 1; i < lines.length; i++) {
          try {
            const evt = JSON.parse(lines[i]);
            if (evt[1] === 'o') events.push({ time: evt[0], data: evt[2] });
          } catch (_) {}
        }
        setPlayerEvents(events);
        setPlayerIndex(0);
        setPlayerPlaying(false);

        // Initialize player terminal
        setTimeout(() => {
          if (playerTermRef.current && !playerTermInstanceRef.current) {
            const t = new Terminal({
              fontFamily: '"IBM Plex Mono", "Fira Code", monospace',
              fontSize: 12,
              cursorBlink: false,
              disableStdin: true,
              theme: { background: '#0a0e17', foreground: '#f9fafb', cursor: '#f59e0b' },
              cols: header.width || 120,
              rows: header.height || 32
            });
            const fit = new FitAddon();
            t.loadAddon(fit);
            t.open(playerTermRef.current);
            fit.fit();
            playerTermInstanceRef.current = t;
            playerFitRef.current = fit;
          }
        }, 100);
      }
    } catch (error) {
      setRecordingsError(error.message || 'Unable to load recording');
    }
  };

  const startPlayer = () => {
    if (!playerEvents.length || !playerTermInstanceRef.current) return;
    setPlayerPlaying(true);
    playerTermInstanceRef.current.clear();
    setPlayerIndex(0);
    let idx = 0;
    const baseTime = playerEvents[0]?.time || 0;
    const playNext = () => {
      if (idx >= playerEvents.length) {
        setPlayerPlaying(false);
        return;
      }
      const evt = playerEvents[idx];
      const delay = idx === 0 ? 0 : Math.min((evt.time - (playerEvents[idx - 1]?.time || 0)) * 1000, 2000);
      playerTimerRef.current = setTimeout(() => {
        if (playerTermInstanceRef.current) {
          playerTermInstanceRef.current.write(evt.data);
        }
        idx++;
        setPlayerIndex(idx);
        playNext();
      }, delay);
    };
    playNext();
  };

  const stopPlayer = () => {
    setPlayerPlaying(false);
    if (playerTimerRef.current) {
      clearTimeout(playerTimerRef.current);
      playerTimerRef.current = null;
    }
  };

  const closePlayer = () => {
    stopPlayer();
    if (playerTermInstanceRef.current) {
      playerTermInstanceRef.current.dispose();
      playerTermInstanceRef.current = null;
      playerFitRef.current = null;
    }
    setCastData(null);
    setCastRecordingId(null);
    setPlayerEvents([]);
    setPlayerIndex(0);
  };

  // ── Shadow session handlers ──
  const openShadow = (session) => {
    closeShadow();
    setShadowSession(session);
    setShadowStatus('connecting');

    setTimeout(() => {
      if (!shadowTermRef.current) return;
      const terminal = new Terminal({
        fontFamily: '"IBM Plex Mono", "Fira Code", monospace',
        fontSize: 13,
        cursorBlink: false,
        disableStdin: true,
        theme: {
          background: '#1a0a2e',
          foreground: '#f9fafb',
          cursor: '#f59e0b'
        }
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.open(shadowTermRef.current);
      fitAddon.fit();
      shadowTermInstanceRef.current = terminal;
      shadowFitRef.current = fitAddon;

      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const wsUrl = `${protocol}://${window.location.host}/api/ws/shadow?token=${encodeURIComponent(
        auth.token
      )}&sessionId=${session.id}`;
      const socket = new WebSocket(wsUrl);
      socket.binaryType = 'arraybuffer';
      shadowSocketRef.current = socket;

      socket.addEventListener('open', () => {
        setShadowStatus('live');
        terminal.writeln('\x1b[33m[SHADOW MODE]\x1b[0m Connected to session #' + session.id + ' — Read-only observation');
        terminal.writeln('');
      });

      socket.addEventListener('message', (event) => {
        if (typeof event.data === 'string') {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'status') {
              terminal.writeln('\x1b[36m[INFO]\x1b[0m ' + payload.message);
            }
          } catch (_) {
            terminal.write(event.data);
          }
          return;
        }
        const decoder = new TextDecoder();
        terminal.write(decoder.decode(event.data));
      });

      socket.addEventListener('close', () => { setShadowStatus('closed'); });
      socket.addEventListener('error', () => { setShadowStatus('error'); });
    }, 100);
  };

  const closeShadow = () => {
    if (shadowSocketRef.current) {
      shadowSocketRef.current.close();
      shadowSocketRef.current = null;
    }
    if (shadowTermInstanceRef.current) {
      shadowTermInstanceRef.current.dispose();
      shadowTermInstanceRef.current = null;
      shadowFitRef.current = null;
    }
    setShadowSession(null);
    setShadowStatus('idle');
  };

  const onChangePassword = async (event) => {
    event.preventDefault();
    setChangePwError('');
    setChangePwSuccess('');
    if (changePwNew !== changePwConfirm) {
      setChangePwError('New passwords do not match');
      return;
    }
    try {
      await changePassword(changePwCurrent, changePwNew);
      setChangePwSuccess('Password changed successfully');
      setChangePwCurrent('');
      setChangePwNew('');
      setChangePwConfirm('');
    } catch (error) {
      setChangePwError(error.message || 'Failed to change password');
    }
  };

  const toggleDarkMode = () => setDarkMode((prev) => !prev);

  const activeSessions = useMemo(
    () => sessions.filter((session) => session.status === 'active'),
    [sessions]
  );

  const filteredAuditItems = useMemo(() => {
    let items = auditItems;
    if (auditFilter) {
      items = items.filter((item) => {
        if (!item.payloadIsJson) return false;
        try {
          const payload = JSON.parse(item.payloadRaw);
          return payload.sessionId === auditFilter;
        } catch (error) {
          return false;
        }
      });
    }
    if (auditTypeFilter) {
      items = items.filter((item) =>
        item.type.toLowerCase().includes(auditTypeFilter.toLowerCase())
      );
    }
    if (auditSearchQuery) {
      const q = auditSearchQuery.toLowerCase();
      items = items.filter((item) =>
        item.type.toLowerCase().includes(q) ||
        item.actor.toLowerCase().includes(q) ||
        (item.payloadRaw || '').toLowerCase().includes(q)
      );
    }
    return items;
  }, [auditFilter, auditItems, auditTypeFilter, auditSearchQuery]);

  const renderAuditDetail = (item) => {
    if (item.payloadIsJson) {
      try {
        const payload = JSON.parse(item.payloadRaw);
        const sessionLabel = payload.sessionId
          ? `Session #${payload.sessionId}`
          : '';
        const resourceLabel = payload.resourceId
          ? `Resource #${payload.resourceId}`
          : '';
        const targetLabel = payload.target ? ` ${payload.target}` : '';
        return `${sessionLabel}${resourceLabel}${targetLabel}`.trim();
      } catch (error) {
        return item.payloadRaw || '';
      }
    }
    return item.payloadRaw || '';
  };

  const renderLogin = () => (
    <div className="login-page">
      <div className="login-card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <span className="badge">EndoriumFort</span>
          <button type="button" className="ghost icon-btn" title={darkMode ? 'Light mode' : 'Dark mode'} onClick={toggleDarkMode}>
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>
        <h1>Sign in</h1>
        <p className="muted">
          Access the WebBastion console to launch remote sessions.
        </p>
        <form className="auth-form" onSubmit={onLogin}>
          <label>
            User
            <input
              name="user"
              value={auth.user}
              onChange={onAuthChange}
              placeholder="ops-admin"
              disabled={twoFARequired}
            />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              value={auth.password}
              onChange={onAuthChange}
              placeholder="Password"
              disabled={twoFARequired}
            />
          </label>
          {twoFARequired && (
            <label>
              Authenticator Code (6 digits)
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="123456"
                autoFocus
                style={{ letterSpacing: '0.3em', textAlign: 'center', fontSize: '1.2em' }}
              />
            </label>
          )}
          <button type="submit">
            {twoFARequired ? 'Verify & Sign in' : 'Sign in'}
          </button>
          {twoFARequired && (
            <button
              type="button"
              className="ghost"
              onClick={() => { setTwoFARequired(false); setTotpCode(''); setAuthError(''); }}
            >
              Back
            </button>
          )}
        </form>
        {authError && <p className="error">{authError}</p>}
      </div>
    </div>
  );

  const renderAdmin = () => (
    <div className="page compact">
      <header className="topbar">
        <div className="brand">
          <span className="badge">EndoriumFort</span>
          <div>
            <h1>Admin Console</h1>
            <p>Manage resources available for operators.</p>
          </div>
        </div>
        <div className="top-actions">
          <button type="button" className="ghost icon-btn" title={darkMode ? 'Light mode' : 'Dark mode'} onClick={toggleDarkMode}>
            {darkMode ? '☀️' : '🌙'}
          </button>
          <button type="button" className="ghost" onClick={() => navigate('/')}
          >
            Back to console
          </button>
          <button type="button" className="secondary" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </header>

      {auth.role !== 'admin' ? (
        <div className="panel reveal">
          <h3>Admin access required</h3>
          <p className="muted">Sign in with the admin role to manage resources.</p>
        </div>
      ) : (
        <div className="admin-grid">
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{editingResourceId ? 'Edit resource' : 'New resource'}</h3>
                <p>Create tiles operators can connect to.</p>
              </div>
            </div>
            <form className="resource-form" onSubmit={onSubmitResource}>
              <label>
                Name
                <input
                  name="name"
                  value={resourceForm.name}
                  onChange={onResourceFieldChange}
                  placeholder="Finance jump host"
                />
              </label>
              <label>
                Target
                <input
                  name="target"
                  value={resourceForm.target}
                  onChange={onResourceFieldChange}
                  placeholder="10.0.0.12"
                />
              </label>
              <label>
                Protocol
                <select
                  name="protocol"
                  value={resourceForm.protocol}
                  onChange={onResourceFieldChange}
                >
                  <option value="ssh">ssh</option>
                  <option value="rdp">rdp</option>
                  <option value="vnc">vnc</option>
                  <option value="http">http</option>
                  <option value="agent">agent (tunnel)</option>
                </select>
              </label>
              <label>
                Port
                <input
                  name="port"
                  type="number"
                  min="1"
                  max="65535"
                  value={resourceForm.port}
                  onChange={onResourceFieldChange}
                />
              </label>
              <label className="full">
                Description
                <input
                  name="description"
                  value={resourceForm.description}
                  onChange={onResourceFieldChange}
                  placeholder="Short usage note"
                />
              </label>
              <label className="full">
                Image URL
                <input
                  name="imageUrl"
                  value={resourceForm.imageUrl}
                  onChange={onResourceFieldChange}
                  placeholder="https://..."
                />
              </label>
              {(resourceForm.protocol === 'http' || resourceForm.protocol === 'https') && (
                <>
                  <label className="full">
                    HTTP Username (optional)
                    <input
                      name="httpUsername"
                      value={resourceForm.httpUsername}
                      onChange={onResourceFieldChange}
                      placeholder="admin"
                      autoComplete="off"
                    />
                  </label>
                  <label className="full">
                    HTTP Password (optional)
                    <input
                      name="httpPassword"
                      type="password"
                      value={resourceForm.httpPassword}
                      onChange={onResourceFieldChange}
                      placeholder="••••••••"
                      autoComplete="new-password"
                    />
                  </label>
                </>
              )}
              {resourceForm.protocol === 'ssh' && (
                <>
                  <label className="full">
                    SSH Username (vault)
                    <input
                      name="sshUsername"
                      value={resourceForm.sshUsername}
                      onChange={onResourceFieldChange}
                      placeholder="root"
                      autoComplete="off"
                    />
                  </label>
                  <label className="full">
                    SSH Password (vault)
                    <input
                      name="sshPassword"
                      type="password"
                      value={resourceForm.sshPassword}
                      onChange={onResourceFieldChange}
                      placeholder={editingResourceId ? 'Leave empty to keep current' : 'Stored securely, injected on connect'}
                      autoComplete="new-password"
                    />
                  </label>
                </>
              )}
              <div className="resource-actions">
                <button type="submit">
                  {editingResourceId ? 'Update' : 'Create'} resource
                </button>
                {editingResourceId && (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      setEditingResourceId(null);
                      setResourceForm({
                        name: '',
                        target: '',
                        protocol: 'ssh',
                        port: '22',
                        description: '',
                        imageUrl: '',
                        httpUsername: '',
                        httpPassword: '',
                        sshUsername: '',
                        sshPassword: ''
                      });
                    }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>
            {resourceError && <p className="error">{resourceError}</p>}
          </div>

          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Resources</h3>
                <p>{resources.length} configured tiles</p>
              </div>
              {loadingResources && <span className="pill loading">loading</span>}
            </div>
            <div className="resource-list">
              {resources.length ? (
                resources.map((resource) => (
                  <article className="resource-row" key={resource.id}>
                    <div>
                      <h4>{resource.name}</h4>
                      <p className="muted">
                        {resource.protocol} {resource.target}:{resource.port}
                      </p>
                      {resource.description && (
                        <p className="muted">{resource.description}</p>
                      )}
                    </div>
                    <div className="resource-actions">
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onEditResource(resource)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onDeleteResource(resource.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </article>
                ))
              ) : (
                <p className="muted">No resources created yet.</p>
              )}
            </div>
          </div>

          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{editingUserId ? 'Edit user' : 'New user'}</h3>
                <p>Create login accounts for the console.</p>
              </div>
              {loadingUsers && <span className="pill loading">loading</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitUser}>
              <label>
                Username
                <input
                  name="username"
                  value={userForm.username}
                  onChange={onUserFieldChange}
                  placeholder="operator01"
                  disabled={!!editingUserId}
                />
              </label>
              <label>
                Password
                <input
                  name="password"
                  type="password"
                  value={userForm.password}
                  onChange={onUserFieldChange}
                  placeholder={editingUserId ? 'New password' : 'Password'}
                />
              </label>
              <label>
                Role
                <select
                  name="role"
                  value={userForm.role}
                  onChange={onUserFieldChange}
                >
                  <option value="operator">operator</option>
                  <option value="admin">admin</option>
                  <option value="auditor">auditor</option>
                </select>
              </label>
              <div className="resource-actions">
                <button type="submit">
                  {editingUserId ? 'Update' : 'Create'} user
                </button>
                {editingUserId && (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => {
                      setEditingUserId(null);
                      setUserForm({
                        username: '',
                        password: '',
                        role: 'operator'
                      });
                    }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>
            {userError && <p className="error">{userError}</p>}
            <div className="resource-list">
              {users.length ? (
                users.map((user) => (
                  <article className="resource-row" key={user.id}>
                    <div>
                      <h4>{user.username}</h4>
                      <p className="muted">Role: {user.role}</p>
                    </div>
                    <div className="resource-actions">
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onEditUser(user)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onLoadUserPermissions(user)}
                      >
                        Permissions
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onDeleteUser(user.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </article>
                ))
              ) : (
                <p className="muted">No users created yet.</p>
              )}
            </div>
          </div>

          {selectedUserForPermissions && (
            <div className="panel reveal">
              <div className="panel-header">
                <div>
                  <h3>Resource Permissions</h3>
                  <p>Assign resources to {selectedUserForPermissions.username}</p>
                </div>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    setSelectedUserForPermissions(null);
                    setUserPermissions([]);
                  }}
                >
                  Close
                </button>
              </div>
              {loadingPermissions && <p>Loading permissions...</p>}
              {permissionsError && <p className="error">{permissionsError}</p>}
              <div className="resource-list">
                {resources.length ? (
                  resources.map((resource) => (
                    <article className="resource-row" key={resource.id}>
                      <div>
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '12px'
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={userPermissions.includes(resource.id)}
                            onChange={() =>
                              onToggleResourcePermission(resource.id)
                            }
                            style={{ cursor: 'pointer' }}
                          />
                          <div>
                            <h4>{resource.name}</h4>
                            <p className="muted">
                              {resource.protocol} {resource.target}:
                              {resource.port}
                            </p>
                          </div>
                        </div>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="muted">No resources yet.</p>
                )}
              </div>
            </div>
          )}

          {/* 2FA Management Panel */}
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Two-Factor Authentication</h3>
                <p>Manage TOTP 2FA for your account.</p>
              </div>
              <span className={`pill ${totpEnabled ? 'ok' : 'loading'}`}>
                {totpEnabled ? 'enabled' : 'disabled'}
              </span>
            </div>
            {totpError && <p className="error">{totpError}</p>}
            {!totpEnabled && !totpSetupData && (
              <div style={{ padding: '12px 0' }}>
                <p className="muted">2FA adds an extra layer of security to your account using an authenticator app (Google Authenticator, Authy, etc.).</p>
                <button type="button" onClick={onSetup2FA} style={{ marginTop: '8px' }}>
                  Setup 2FA
                </button>
              </div>
            )}
            {totpSetupData && (
              <div style={{ padding: '12px 0' }}>
                <p>Scan this QR code with your authenticator app, or manually enter the secret:</p>
                <div style={{
                  background: '#fff',
                  display: 'inline-block',
                  padding: '16px',
                  borderRadius: '8px',
                  margin: '12px 0'
                }}>
                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpSetupData.otpauthUri)}`}
                    alt="TOTP QR Code"
                    width={200}
                    height={200}
                  />
                </div>
                <p className="muted" style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  Secret: {totpSetupData.secret}
                </p>
                <label>
                  Enter code from your authenticator
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpSetupCode}
                    onChange={(e) => setTotpSetupCode(e.target.value)}
                    placeholder="123456"
                    style={{ letterSpacing: '0.3em', textAlign: 'center' }}
                  />
                </label>
                <div className="resource-actions" style={{ marginTop: '8px' }}>
                  <button type="button" onClick={onVerify2FA}>
                    Verify &amp; Enable
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => { setTotpSetupData(null); setTotpSetupCode(''); }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            {totpEnabled && (
              <div style={{ padding: '12px 0' }}>
                <p className="muted">2FA is currently active. Enter a code from your authenticator to disable it.</p>
                <label>
                  Current TOTP code
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpDisableCode}
                    onChange={(e) => setTotpDisableCode(e.target.value)}
                    placeholder="123456"
                    style={{ letterSpacing: '0.3em', textAlign: 'center' }}
                  />
                </label>
                <button
                  type="button"
                  className="ghost"
                  onClick={onDisable2FA}
                  style={{ marginTop: '8px' }}
                >
                  Disable 2FA
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );

  const renderMain = () => (
    <div className="page compact">
      <header className="topbar">
        <div className="brand">
          <span className="badge">EndoriumFort</span>
          <div>
            <h1>WebBastion Console</h1>
            <p>Minimal access console for SSH sessions and live supervision.</p>
          </div>
        </div>
        <div className="top-actions">
          <div className="health">
            <span className={`pill ${status}`}>{status}</span>
            <span className="detail">{detail}</span>
          </div>
          <div className="nav-actions">
            {auth.role === 'admin' && (
              <button
                type="button"
                className="secondary"
                onClick={() => navigate('/admin')}
              >
                Admin
              </button>
            )}
            <button type="button" className="ghost" onClick={() => openAudit()}>
              View audit log
            </button>
            {(auth.role === 'admin' || auth.role === 'auditor') && (
              <button type="button" className="ghost" onClick={() => openRecordings()}>
                Recordings
              </button>
            )}
            <button type="button" className="ghost" onClick={() => setChangePwOpen(true)}>
              Change password
            </button>
            <button type="button" className="ghost icon-btn" title={darkMode ? 'Light mode' : 'Dark mode'} onClick={toggleDarkMode}>
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button type="button" className="ghost" onClick={onLogout}>
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* ── Dashboard Stats ── */}
      {stats && (
        <section className="stats-grid reveal">
          <div className="stat-card">
            <div className="stat-icon stat-sessions">⚡</div>
            <div>
              <h4>{stats.sessions?.active || 0}</h4>
              <p className="muted">Active sessions</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-total">📊</div>
            <div>
              <h4>{stats.sessions?.total || 0}</h4>
              <p className="muted">Total sessions</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-resources">🖥️</div>
            <div>
              <h4>{stats.resources?.total || 0}</h4>
              <p className="muted">Resources</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-users">👤</div>
            <div>
              <h4>{stats.users?.total || 0}</h4>
              <p className="muted">Users</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-recordings">🎬</div>
            <div>
              <h4>{stats.recordings?.total || 0}</h4>
              <p className="muted">Recordings</p>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon stat-tokens">🔑</div>
            <div>
              <h4>{stats.auth?.activeTokens || 0}</h4>
              <p className="muted">Active tokens</p>
            </div>
          </div>
        </section>
      )}

      <section className="panel resources-panel reveal">
        <div className="panel-header">
          <div>
            <h3>Resources</h3>
            <p>Select a resource tile to connect instantly.</p>
          </div>
          <div className="status-row">
            {loadingResources ? (
              <span className="pill loading">loading</span>
            ) : (
              <span className="pill ok">{resources.length} tiles</span>
            )}
          </div>
        </div>
        {resourceError && <p className="error">{resourceError}</p>}
        <div className="resource-tiles">
          {resources.length ? (
            resources.map((resource) => (
              <button
                type="button"
                className="resource-tile"
                key={resource.id}
                onClick={() => onConnectResource(resource)}
              >
                <div
                  className="resource-thumb"
                  style={
                    resource.imageUrl
                      ? { backgroundImage: `url(${resource.imageUrl})` }
                      : undefined
                  }
                >
                  {!resource.imageUrl && (
                    <span className="resource-letter">
                      {resource.name ? resource.name[0] : 'R'}
                    </span>
                  )}
                </div>
                <div className="resource-info">
                  <h4>{resource.name}</h4>
                  <p className="muted">
                    {resource.protocol} {resource.target}:{resource.port}
                  </p>
                  {resource.description && (
                    <p className="muted">{resource.description}</p>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  {resource.hasCredentials && (
                    <span className="pill ok" title="Credentials stored in vault" style={{ fontSize: '0.65rem' }}>🔐 vault</span>
                  )}
                  {resource.protocol === 'agent' ? (
                    <span className="pill loading" style={{ fontSize: '0.65rem' }}>🚀 launch</span>
                  ) : (
                    <span className="pill ready">connect</span>
                  )}
                </div>
              </button>
            ))
          ) : (
            <p className="muted">No resources yet. Ask an admin to add one.</p>
          )}
        </div>
      </section>

      <section className="main-grid">
        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Sessions</h3>
              <p>Start, supervise, and terminate SSH access.</p>
            </div>
            <div className="status-row">
              {loadingSessions ? (
                <span className="pill loading">loading</span>
              ) : (
                <span className="pill ok">{activeSessions.length} active</span>
              )}
            </div>
          </div>
          {sessionError && <p className="error">{sessionError}</p>}

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
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => openAudit(session.id)}
                  >
                    Open audit
                  </button>
                  {(auth.role === 'admin' || auth.role === 'auditor') && (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => openRecordings(session.id)}
                    >
                      Recordings
                    </button>
                  )}
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => openTerminal(session)}
                    disabled={session.status !== 'active'}
                  >
                    Open live
                  </button>
                  {(auth.role === 'admin' || auth.role === 'auditor') &&
                    session.status === 'active' && (
                      <button
                        type="button"
                        className="ghost shadow-btn"
                        onClick={() => openShadow(session)}
                        title="Observe this session in real-time (read-only)"
                      >
                        👁 Shadow
                      </button>
                    )}
                </div>
              </article>
            ))}
          </div>
        </div>
        {auditOpen && (
          <div className="panel audit-panel reveal">
            <div className="panel-header">
              <div>
                <h3>Audit log</h3>
                <p>Recent audit events and session actions.</p>
              </div>
              <div className="status-row">
                {loadingAudit ? (
                  <span className="pill loading">loading</span>
                ) : (
                  <span className="pill ok">{filteredAuditItems.length} events</span>
                )}
              </div>
            </div>
            <div className="audit-controls">
              <button
                type="button"
                className="secondary"
                onClick={loadAudit}
                disabled={loadingAudit}
              >
                Refresh
              </button>
              {auditFilter && (
                <button
                  type="button"
                  className="ghost"
                  onClick={() => setAuditFilter(null)}
                >
                  Clear filter
                </button>
              )}
              <button
                type="button"
                className="ghost"
                onClick={() => setAuditOpen(false)}
              >
                Hide
              </button>
            </div>
            <div className="audit-search-row">
              <input
                type="text"
                placeholder="Search events..."
                value={auditSearchQuery}
                onChange={(e) => setAuditSearchQuery(e.target.value)}
                style={{ flex: 1, maxWidth: '280px' }}
              />
              <select
                value={auditTypeFilter}
                onChange={(e) => setAuditTypeFilter(e.target.value)}
                style={{ maxWidth: '200px' }}
              >
                <option value="">All types</option>
                <option value="auth.login">Login</option>
                <option value="auth.logout">Logout</option>
                <option value="auth.login.failure">Login Failure</option>
                <option value="session.create">Session Create</option>
                <option value="session.terminate">Session Terminate</option>
                <option value="session.close">Session Close</option>
                <option value="resource">Resource</option>
                <option value="user">User</option>
                <option value="credential">Credential</option>
                <option value="tunnel">Tunnel</option>
              </select>
            </div>
            {auditError && <p className="error">{auditError}</p>}
            {auth.role !== 'admin' && auth.role !== 'auditor' && (
              <p className="muted">Sign in with auditor or admin role.</p>
            )}
            {(auth.role === 'admin' || auth.role === 'auditor') && (
              <div className="audit-list">
                {filteredAuditItems.length ? (
                  filteredAuditItems.map((item) => (
                    <article className="audit-item" key={item.id}>
                      <div>
                        <h4>{item.type}</h4>
                        <p className="muted">
                          {renderAuditDetail(item) || 'No session data'}
                        </p>
                      </div>
                      <div className="audit-meta">
                        <span className="muted">{item.actor}</span>
                        <span className="muted">{item.createdAt}</span>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="muted">No audit events available.</p>
                )}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Recordings panel */}
      {recordingsOpen && (
        <section className="panel reveal" style={{ marginBottom: '24px' }}>
          <div className="panel-header">
            <div>
              <h3>Session Recordings</h3>
              <p>Replay SSH sessions recorded in Asciinema format.</p>
            </div>
            <div className="status-row">
              {loadingRecordings ? (
                <span className="pill loading">loading</span>
              ) : (
                <span className="pill ok">{recordings.length} recordings</span>
              )}
            </div>
          </div>
          <div className="audit-controls">
            <button type="button" className="secondary" onClick={() => loadRecordings()} disabled={loadingRecordings}>
              Refresh
            </button>
            <button type="button" className="ghost" onClick={() => { setRecordingsOpen(false); setCastData(null); }}>
              Hide
            </button>
          </div>
          {recordingsError && <p className="error">{recordingsError}</p>}
          <div className="audit-list">
            {recordings.length ? (
              recordings.map((rec) => (
                <article className="audit-item" key={rec.id}>
                  <div>
                    <h4>Recording #{rec.id} — Session #{rec.sessionId}</h4>
                    <p className="muted">
                      Duration: {rec.durationMs ? `${(rec.durationMs / 1000).toFixed(1)}s` : 'in progress'} —
                      Size: {rec.fileSize ? `${(rec.fileSize / 1024).toFixed(1)} KB` : '—'}
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
              <p className="muted">No recordings available.</p>
            )}
          </div>
          {castData && (
            <div style={{ marginTop: '16px', background: '#111827', borderRadius: '8px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <h4 style={{ color: '#f9fafb', margin: 0 }}>Replay — Recording #{castRecordingId}</h4>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {!playerPlaying ? (
                    <button
                      type="button"
                      className="secondary"
                      onClick={startPlayer}
                      style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
                    >
                      ▶ Play
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="secondary"
                      onClick={stopPlayer}
                      style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
                    >
                      ⏸ Pause
                    </button>
                  )}
                  <span style={{ color: '#9ca3af', fontSize: '0.8rem' }}>
                    {playerIndex}/{playerEvents.length} events
                  </span>
                  <button
                    type="button"
                    className="ghost"
                    onClick={closePlayer}
                    style={{ color: '#9ca3af' }}
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
              <p className="muted" style={{ marginTop: '8px', fontSize: '11px' }}>
                Animated replay powered by xterm.js. Click Play to watch the session unfold in real time.
              </p>
            </div>
          )}
        </section>
      )}

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

      {/* Shadow session panel */}
      {shadowSession && (
        <section className="panel terminal-panel shadow-panel reveal">
          <div className="panel-header">
            <div>
              <h3>👁 Shadow — Session #{shadowSession.id}</h3>
              <p>
                Read-only observation of{' '}
                <strong>{shadowSession.user}</strong> → <strong>{shadowSession.target}</strong>
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span className={`pill ${shadowStatus === 'live' ? 'ok' : shadowStatus === 'error' ? 'error' : 'loading'}`}>
                {shadowStatus}
              </span>
              <button type="button" className="secondary" onClick={closeShadow}>
                Close
              </button>
            </div>
          </div>
          <div className="terminal-shell shadow-terminal" ref={shadowTermRef} />
        </section>
      )}

      {/* Agent launch modal */}
      {agentModal && (
        <div className="modal-overlay" onClick={() => setAgentModal(null)}>
          <div className="modal-content agent-modal" onClick={(e) => e.stopPropagation()}>
            <div className="agent-modal-header">
              <span className="agent-icon">🚀</span>
              <div>
                <h3>Agent Tunnel</h3>
                <p className="muted">Connexion via l'agent local EndoriumFort</p>
              </div>
            </div>
            <div className="agent-modal-info">
              <div className="agent-info-row">
                <span className="agent-label">Ressource</span>
                <span className="agent-value">{agentModal.resource.name}</span>
              </div>
              <div className="agent-info-row">
                <span className="agent-label">Cible</span>
                <span className="agent-value">{agentModal.resource.target}:{agentModal.resource.port}</span>
              </div>
              <div className="agent-info-row">
                <span className="agent-label">Port local</span>
                <span className="agent-value">127.0.0.1:{agentModal.port}</span>
              </div>
            </div>
            <div className="agent-command-block">
              <label className="agent-label">Commande à exécuter dans un terminal :</label>
              <div className="agent-command-row">
                <code className="agent-command">{agentModal.command}</code>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => {
                    navigator.clipboard.writeText(agentModal.command);
                    setAgentModal((prev) => ({ ...prev, copied: true }));
                    setTimeout(() => setAgentModal((prev) => prev ? ({ ...prev, copied: false }) : null), 2000);
                  }}
                >
                  {agentModal.copied ? '✓ Copié' : '📋 Copier'}
                </button>
              </div>
            </div>
            <div className="agent-modal-tip">
              <p>💡 Une fois le tunnel actif, ouvrez <a href={`http://127.0.0.1:${agentModal.port}`} target="_blank" rel="noreferrer">http://127.0.0.1:{agentModal.port}</a> dans votre navigateur.</p>
            </div>
            <div className="agent-modal-actions">
              <button
                type="button"
                onClick={() => {
                  const randomPort = 10000 + Math.floor(Math.random() * 50000);
                  const serverUrl = window.location.origin;
                  const cmd = `endoriumfort-agent connect --server ${serverUrl} --token ${auth.token} --resource ${agentModal.resource.id} --local-port ${randomPort}`;
                  setAgentModal((prev) => ({ ...prev, port: randomPort, command: cmd, copied: false }));
                }}
                className="ghost"
              >
                🔄 Nouveau port
              </button>
              <button type="button" className="ghost" onClick={() => setAgentModal(null)}>Fermer</button>
            </div>
          </div>
        </div>
      )}

      {/* Change password modal */}
      {changePwOpen && (
        <div className="modal-overlay" onClick={() => setChangePwOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Change Password</h3>
            <form onSubmit={onChangePassword}>
              <label>
                Current password
                <input type="password" value={changePwCurrent}
                  onChange={(e) => setChangePwCurrent(e.target.value)} required />
              </label>
              <label>
                New password
                <input type="password" value={changePwNew}
                  onChange={(e) => setChangePwNew(e.target.value)} required
                  placeholder="Min 8 chars, upper + lower + digit" />
              </label>
              <label>
                Confirm new password
                <input type="password" value={changePwConfirm}
                  onChange={(e) => setChangePwConfirm(e.target.value)} required />
              </label>
              {changePwError && <p className="error">{changePwError}</p>}
              {changePwSuccess && <p className="success">{changePwSuccess}</p>}
              <div style={{display:'flex',gap:'0.8rem',marginTop:'0.8rem'}}>
                <button type="submit">Change</button>
                <button type="button" className="ghost" onClick={() => {
                  setChangePwOpen(false); setChangePwError(''); setChangePwSuccess('');
                  setChangePwCurrent(''); setChangePwNew(''); setChangePwConfirm('');
                }}>Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );

  if (route === '/login') {
    return renderLogin();
  }
  if (route === '/admin') {
    return renderAdmin();
  }
  if (route === '/webproxy') {
    return (
      <WebProxyViewer
        resourceId={webProxyResourceId}
        token={webProxyToken}
        resourceName={webProxyResourceName}
        onNavigate={navigate}
      />
    );
  }
  return renderMain();
}

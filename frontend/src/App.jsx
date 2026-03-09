import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
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
  issueEphemeralCredential,
  consumeEphemeralCredential,
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
  verify2FA,
  fetchAccessRequests,
  createAccessRequest,
  approveAccessRequest,
  denyAccessRequest
} from './api.js';

const ROLE_BLUEPRINTS = [
  {
    id: 'operator',
    label: 'Session Operator',
    description: 'Launch and manage remote sessions on authorized resources.',
    permissions: ['Start and terminate sessions', 'Use SSH/web/agent access paths', 'View personal operations data']
  },
  {
    id: 'admin',
    label: 'Platform Admin',
    description: 'Govern users, resources, and assignment policies.',
    permissions: ['Create and edit users', 'Manage resources and credentials', 'Assign resource permissions']
  },
  {
    id: 'auditor',
    label: 'Security Auditor',
    description: 'Monitor traceability and investigate security events.',
    permissions: ['Read audit events', 'Replay session recordings', 'Access governance metrics']
  }
];

const normalizeRole = (role) => {
  const value = String(role || '').toLowerCase();
  if (value === 'platform_admin' || value === 'access_admin') return 'admin';
  if (value === 'session_operator') return 'operator';
  if (value === 'security_auditor' || value === 'security_analyst') return 'auditor';
  return value || 'operator';
};

const roleLabel = (role) => {
  const mapped = normalizeRole(role);
  const found = ROLE_BLUEPRINTS.find((item) => item.id === mapped);
  return found ? found.label : mapped;
};

const hasRoleCapability = (role, capability) => {
  const mapped = normalizeRole(role);
  if (mapped === 'admin') return true;
  if (mapped === 'operator') {
    return ['operateSessions', 'viewStats'].includes(capability);
  }
  if (mapped === 'auditor') {
    return ['viewAudit', 'viewRecordings', 'viewStats'].includes(capability);
  }
  return false;
};

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
          return { user: parsed.user || '', password: '', role: normalizeRole(parsed.role), token: parsed.token };
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
  const [terminalReady, setTerminalReady] = useState(false);
  const [autoConnectSessionId, setAutoConnectSessionId] = useState(null);
  const [auditOpen, setAuditOpen] = useState(false);
  const [auditItems, setAuditItems] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [auditFilter, setAuditFilter] = useState(null);
  const [resources, setResources] = useState([]);
  const [loadingResources, setLoadingResources] = useState(false);
  const [savingResource, setSavingResource] = useState(false);
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
    sshPassword: '',
    requireAccessJustification: false,
    requireDualApproval: false,
    enableCommandGuard: false,
    adaptiveAccessPolicy: false,
    riskLevel: 'low'
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
  const [route, setRoute] = useState(() =>
    window.location.pathname ? window.location.pathname : '/'
  );
  const [mainTab, setMainTab] = useState('sessions');
  const [inlineWebResource, setInlineWebResource] = useState(null);
  const [accessPromptResource, setAccessPromptResource] = useState(null);
  const [accessPromptReason, setAccessPromptReason] = useState('');
  const [accessPromptTicketId, setAccessPromptTicketId] = useState('');
  const [accessPromptMode, setAccessPromptMode] = useState('connect');
  const [accessRequests, setAccessRequests] = useState([]);
  const [loadingAccessRequests, setLoadingAccessRequests] = useState(false);
  const [accessRequestError, setAccessRequestError] = useState('');
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
  const [quickRefreshing, setQuickRefreshing] = useState(false);
  const [securityAuditItems, setSecurityAuditItems] = useState([]);
  const [loadingSecurityAudit, setLoadingSecurityAudit] = useState(false);
  const [securityAuditError, setSecurityAuditError] = useState('');
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

  const canManagePlatform = hasRoleCapability(auth.role, 'manageResources');
  const canViewAudit = hasRoleCapability(auth.role, 'viewAudit');
  const canViewRecordings = hasRoleCapability(auth.role, 'viewRecordings');
  const canOperateSessions = hasRoleCapability(auth.role, 'operateSessions');
  const roleName = roleLabel(auth.role);
  const tabGuide = useMemo(() => {
    const base = {
      overview: {
        title: 'Overview',
        hint: 'Use this page for global posture and rapid checks.',
        focus: 'Review posture and recent sessions.'
      },
      sessions: {
        title: 'Sessions',
        hint: 'Operate live access and intervene when needed.',
        focus: 'Start, monitor, and terminate active sessions.'
      },
      audit: {
        title: 'Audit',
        hint: 'Investigate events and validate user actions.',
        focus: 'Filter and inspect traceability records.'
      },
      recordings: {
        title: 'Recordings',
        hint: 'Replay session evidence for forensic analysis.',
        focus: 'Open SSH cast files and inspect timelines.'
      }
    };
    return base[mainTab] || base.overview;
  }, [mainTab]);

  const missionBoardEntries = useMemo(() => {
    const entries = [
      {
        id: 'sessions',
        stage: 'Operate',
        title: 'Live Access',
        shortcut: 'Alt+1',
        hint: 'Run and supervise remote sessions in real time.'
      },
      {
        id: 'audit',
        stage: 'Trace',
        title: 'Investigation',
        shortcut: 'Alt+2',
        hint: 'Hunt activity trails and suspicious sequences.'
      },
      {
        id: 'recordings',
        stage: 'Evidence',
        title: 'Replay Vault',
        shortcut: 'Alt+3',
        hint: 'Replay captured sessions and validate behavior.',
        hidden: !canViewRecordings
      }
    ];

    return entries.filter((entry) => !entry.hidden);
  }, [canViewRecordings]);

  const pendingAccessApprovals = useMemo(() => {
    return accessRequests
      .filter((item) => item.status === 'pending')
      .sort((a, b) => {
        const ta = Date.parse(a.createdAt || '') || 0;
        const tb = Date.parse(b.createdAt || '') || 0;
        return tb - ta;
      })
      .slice(0, 6);
  }, [accessRequests]);

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

  useEffect(() => {
    const onUnauthorized = () => {
      setAuth((prev) => ({ ...prev, token: '', password: '' }));
      setAuthError('Session expirée. Veuillez vous reconnecter.');
      setTokenExpiresAt('');
      setAuthToken('');
      navigate('/login');
    };
    window.addEventListener('endoriumfort:unauthorized', onUnauthorized);
    return () => window.removeEventListener('endoriumfort:unauthorized', onUnauthorized);
  }, []);

  // Dark mode effect
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light');
    localStorage.setItem('endoriumfort_darkmode', darkMode ? 'true' : 'false');
  }, [darkMode]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.altKey && !event.metaKey && !event.ctrlKey) {
        const jumpMap = {
          '1': 'sessions',
          '2': 'audit',
          '3': canViewRecordings ? 'recordings' : null
        };
        const destination = jumpMap[event.key];
        if (destination) {
          event.preventDefault();
          setMainTab(destination);
          return;
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [canViewRecordings]);

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
    if (!auth.token) {
      setAccessRequests([]);
      setLoadingAccessRequests(false);
      return;
    }
    let active = true;
    setLoadingAccessRequests(true);
    fetchAccessRequests()
      .then((data) => {
        if (!active) return;
        setAccessRequests(Array.isArray(data.items) ? data.items : []);
        setAccessRequestError('');
      })
      .catch((error) => {
        if (!active) return;
        setAccessRequestError(error.message || 'Unable to load access requests');
      })
      .finally(() => {
        if (!active) return;
        setLoadingAccessRequests(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
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
  }, [auth.token, canManagePlatform]);

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

  useEffect(() => {
    if (!auth.token || !canViewAudit) {
      setSecurityAuditItems([]);
      setSecurityAuditError('');
      return;
    }
    let active = true;
    const load = () => {
      setLoadingSecurityAudit(true);
      fetchAudit()
        .then((data) => {
          if (!active) return;
          setSecurityAuditItems(Array.isArray(data.items) ? data.items : []);
          setSecurityAuditError('');
        })
        .catch((error) => {
          if (!active) return;
          setSecurityAuditError(error.message || 'Unable to load security feed');
        })
        .finally(() => {
          if (active) setLoadingSecurityAudit(false);
        });
    };
    load();
    const interval = setInterval(load, 20000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [auth.token, canViewAudit]);

  const onAuthChange = (event) => {
    const { name, value } = event.target;
    setAuth((prev) => ({ ...prev, [name]: value }));
  };

  const onResourceFieldChange = (event) => {
    const { name, value, type, checked } = event.target;
    const nextValue = type === 'checkbox' ? checked : value;
    setResourceForm((prev) => ({ ...prev, [name]: nextValue }));
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
        role: normalizeRole(payload.role),
        user: payload.user,
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: normalizeRole(payload.role)
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

  const onQuickRefresh = async () => {
    if (!auth.token || quickRefreshing) {
      return;
    }
    setQuickRefreshing(true);
    try {
      const requests = [fetchSessions(), fetchResources(), fetchStats()];
      if (canManagePlatform) {
        requests.push(fetchUsers());
      }
      if (canViewAudit) {
        requests.push(fetchAudit());
      }
      const results = await Promise.all(requests);
      const [sessionData, resourceData, statsData, maybeUsersOrAudit, maybeAudit] = results;

      setSessions(Array.isArray(sessionData?.items) ? sessionData.items : []);
      setResources(Array.isArray(resourceData?.items) ? resourceData.items : []);
      setStats(statsData || null);
      if (canManagePlatform) {
        setUsers(Array.isArray(maybeUsersOrAudit?.items) ? maybeUsersOrAudit.items : []);
      }
      if (canViewAudit) {
        const auditData = canManagePlatform ? maybeAudit : maybeUsersOrAudit;
        const items = Array.isArray(auditData?.items) ? auditData.items : [];
        setSecurityAuditItems(items);
        if (auditOpen) {
          setAuditItems(items);
        }
      }
      setSessionError('');
      setResourceError('');
      setUserError('');
      setSecurityAuditError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to refresh data');
    } finally {
      setQuickRefreshing(false);
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
    setMainTab('audit');
    setAuditOpen(true);
    setAuditFilter(sessionId);
    loadAudit();
  };

  useEffect(() => {
    // Terminal DOM node exists only in the Sessions tab.
    if (mainTab !== 'sessions' || !activeTerminalSession || !terminalRef.current) {
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
    setTerminalReady(true);

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
      setTerminalReady(false);
    };
  }, [activeTerminalSession, mainTab]);

  useEffect(() => {
    if (!autoConnectSessionId) return;
    if (mainTab !== 'sessions') return;
    if (!terminalReady) return;
    if (!auth.token || !sshPassword) return;
    if (!activeTerminalSession || activeTerminalSession.id !== autoConnectSessionId) return;

    setAutoConnectSessionId(null);
    connectTerminal();
  }, [
    autoConnectSessionId,
    mainTab,
    terminalReady,
    auth.token,
    sshPassword,
    activeTerminalSession
  ]);

  const openTerminal = (session) => {
    setActiveTerminalSession(session);
    setSshPassword('');
    setTerminalError('');
    setTerminalStatus('idle');
    setTerminalReady(false);
  };

  const buildWebSocketUrl = (path, params = {}) => {
    const host = window.location.hostname || '';
    const isLocalHost = host === 'localhost' || host === '127.0.0.1' || host === '::1';
    const wsProtocol = (window.location.protocol === 'https:' || !isLocalHost) ? 'wss:' : 'ws:';
    const url = new URL(path, window.location.origin);
    url.protocol = wsProtocol;
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    });
    return url.toString();
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
      setTerminalError('Terminal is initializing... retrying.');
      window.setTimeout(() => {
        if (terminalInstanceRef.current && auth.token && activeTerminalSession) {
          connectTerminal();
        }
      }, 150);
      return;
    }

    const wsUrl = buildWebSocketUrl('/api/ws/ssh');
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
      setTerminalError('WebSocket error. Vérifie HTTPS/WSS, token et proxy Nginx.');
    });
  };

  const connectToResource = async (resource, accessMeta = {}) => {
    if (!auth.token) {
      setSessionError('Sign in to start a session.');
      return false;
    }

    // Handle web resources via proxy
    if (resource.protocol === 'http' || resource.protocol === 'https') {
      setInlineWebResource(resource);
      setMainTab('sessions');
      return true;
    }

    // Handle agent resources — open agent launch modal with random port
    if (resource.protocol === 'agent') {
      const randomPort = 10000 + Math.floor(Math.random() * 50000);
      const serverUrl = window.location.origin;
      const cmd = `endoriumfort-agent connect --server ${serverUrl} --token ${auth.token} --resource ${resource.id} --local-port ${randomPort}`;
      setAgentModal({ resource, port: randomPort, command: cmd, copied: false });
      return true;
    }

    // Handle SSH/other protocols
    try {
      const payload = {
        resourceId: resource.id,
        target: resource.target,
        user: resource.sshUsername || auth.user,
        protocol: resource.protocol,
        port: resource.port,
        justification: (accessMeta.justification || '').trim(),
        ticketId: (accessMeta.ticketId || '').trim(),
        accessRequestId: accessMeta.accessRequestId || undefined
      };
      const created = await createSession(payload);
      setSessions((prev) => [created, ...prev]);
      setSessionError('');
      setInlineWebResource(null);
      openTerminal(created);

      // Auto-inject credentials if stored in the vault
      if (resource.hasCredentials) {
        try {
          const lease = await issueEphemeralCredential(resource.id);
          const creds = await consumeEphemeralCredential(lease.leaseId);
          if (creds.sshPassword) {
            setSshPassword(creds.sshPassword);
            setMainTab('sessions');
            setAutoConnectSessionId(created.id);
          }
        } catch (_) {
          // Fallback to static vault credentials if ephemeral lease fails.
          try {
            const creds = await fetchResourceCredentials(resource.id);
            if (creds.sshPassword) {
              setSshPassword(creds.sshPassword);
              setMainTab('sessions');
              setAutoConnectSessionId(created.id);
            }
          } catch (_) {
            // Silently fallback to manual password entry
          }
        }
      }
      return true;
    } catch (error) {
      setSessionError(error.message || 'Unable to create session');
      return false;
    }
  };

  const onConnectResource = async (resource) => {
    if (resource.requireDualApproval && normalizeRole(auth.role) !== 'admin') {
      const approved = accessRequests.find(
        (item) =>
          item.resourceId === resource.id &&
          item.requester === auth.user &&
          item.status === 'approved'
      );
      if (approved) {
        await connectToResource(resource, {
          justification: approved.justification || '',
          ticketId: approved.ticketId || '',
          accessRequestId: approved.id
        });
        return;
      }
      setAccessPromptMode('request');
      setAccessPromptResource(resource);
      setAccessPromptReason('');
      setAccessPromptTicketId('');
      return;
    }

    if (resource.requireAccessJustification) {
      setAccessPromptMode('connect');
      setAccessPromptResource(resource);
      setAccessPromptReason('');
      setAccessPromptTicketId('');
      return;
    }
    await connectToResource(resource);
  };

  const onSubmitAccessPrompt = async (event) => {
    event.preventDefault();
    if (!accessPromptResource) {
      return;
    }
    const reason = accessPromptReason.trim();
    if (!reason) {
      setSessionError('Access reason is required for this resource.');
      return;
    }
    if (accessPromptMode === 'request') {
      try {
        const created = await createAccessRequest({
          resourceId: accessPromptResource.id,
          justification: reason,
          ticketId: accessPromptTicketId.trim()
        });
        setAccessRequests((prev) => [created, ...prev]);
        setSessionError('Access request submitted. Wait for admin approval.');
        setAccessPromptResource(null);
        setAccessPromptReason('');
        setAccessPromptTicketId('');
        setAccessPromptMode('connect');
        return;
      } catch (error) {
        setSessionError(error.message || 'Unable to submit access request');
        return;
      }
    }
    const connected = await connectToResource(accessPromptResource, {
      justification: reason,
      ticketId: accessPromptTicketId.trim()
    });
    if (connected) {
      setAccessPromptResource(null);
      setAccessPromptReason('');
      setAccessPromptTicketId('');
      setAccessPromptMode('connect');
    }
  };

  const onApproveAccessRequest = async (requestId) => {
    try {
      const updated = await approveAccessRequest(requestId);
      setAccessRequests((prev) =>
        prev.map((item) => (item.id === requestId ? updated : item))
      );
      setAccessRequestError('');
    } catch (error) {
      setAccessRequestError(error.message || 'Unable to approve access request');
    }
  };

  const onDenyAccessRequest = async (requestId) => {
    try {
      const updated = await denyAccessRequest(requestId);
      setAccessRequests((prev) =>
        prev.map((item) => (item.id === requestId ? updated : item))
      );
      setAccessRequestError('');
    } catch (error) {
      setAccessRequestError(error.message || 'Unable to deny access request');
    }
  };

  const onSubmitResource = async (event) => {
    event.preventDefault();
    if (savingResource) {
      return;
    }
    setResourceError('');

    const trimmedName = resourceForm.name.trim();
    const trimmedTarget = resourceForm.target.trim();
    const selectedProtocol = (resourceForm.protocol || '').trim();
    if (!trimmedName || !trimmedTarget || !selectedProtocol) {
      setResourceError('Name, target and protocol are required.');
      return;
    }

    const payload = {
      name: trimmedName,
      target: trimmedTarget,
      protocol: selectedProtocol,
      port: Number.parseInt(resourceForm.port, 10) || 22,
      description: resourceForm.description.trim(),
      imageUrl: resourceForm.imageUrl.trim(),
      httpUsername: resourceForm.httpUsername.trim(),
      httpPassword: resourceForm.httpPassword,
      sshUsername: resourceForm.sshUsername.trim(),
      sshPassword: resourceForm.sshPassword,
      requireAccessJustification: !!resourceForm.requireAccessJustification,
      requireDualApproval: !!resourceForm.requireDualApproval,
      enableCommandGuard: !!resourceForm.enableCommandGuard,
      adaptiveAccessPolicy: !!resourceForm.adaptiveAccessPolicy,
      riskLevel: resourceForm.riskLevel || 'low'
    };
    try {
      setSavingResource(true);
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
        sshPassword: '',
        requireAccessJustification: false,
        requireDualApproval: false,
        enableCommandGuard: false,
        adaptiveAccessPolicy: false,
        riskLevel: 'low'
      });
    } catch (error) {
      setResourceError(error.message || 'Unable to save resource');
    } finally {
      setSavingResource(false);
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
      sshPassword: '',
      requireAccessJustification: !!resource.requireAccessJustification,
      requireDualApproval: !!resource.requireDualApproval,
      enableCommandGuard: !!resource.enableCommandGuard,
      adaptiveAccessPolicy: !!resource.adaptiveAccessPolicy,
      riskLevel: resource.riskLevel || 'low'
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

  useEffect(() => {
    if (!auth.token) return;
    if (mainTab === 'audit') {
      loadAudit();
    }
    if (mainTab === 'recordings' && canViewRecordings) {
      loadRecordings();
    }
  }, [mainTab, auth.token, canViewRecordings]);

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
    setMainTab('recordings');
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

      const wsUrl = buildWebSocketUrl('/api/ws/shadow', {
        sessionId: session.id
      });
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

  const sortedSessions = useMemo(() => {
    return [...sessions].sort((a, b) => {
      const ta = Date.parse(a.createdAt || '') || 0;
      const tb = Date.parse(b.createdAt || '') || 0;
      return tb - ta;
    });
  }, [sessions]);

  const recentSessions = useMemo(
    () => sortedSessions.slice(0, 6),
    [sortedSessions]
  );

  const securityAlerts = useMemo(() => {
    const now = Date.now();
    const audits = securityAuditItems;
    const loginFailures30m = audits.filter((item) => {
      if (!item?.type || !item?.createdAt) return false;
      const t = Date.parse(item.createdAt) || 0;
      if (t < now - 30 * 60 * 1000) return false;
      return item.type.includes('auth.login.failure') || item.type.includes('auth.rate_limit');
    }).length;

    const staleActiveCount = activeSessions.filter((session) => {
      const t = Date.parse(session.createdAt || '') || 0;
      return t > 0 && t < now - 6 * 60 * 60 * 1000;
    }).length;

    const adminOps24h = audits.filter((item) => {
      if (!item?.type || !item?.createdAt) return false;
      const t = Date.parse(item.createdAt) || 0;
      if (t < now - 24 * 60 * 60 * 1000) return false;
      return item.type.startsWith('resource.') || item.type.startsWith('user.');
    }).length;

    return [
      {
        key: 'failures',
        severity: loginFailures30m >= 5 ? 'critical' : loginFailures30m > 0 ? 'warning' : 'ok',
        title: 'Login failures (30m)',
        value: loginFailures30m,
        hint: loginFailures30m > 0 ? 'Investigate source IP and actor patterns in audit logs.' : 'No unusual authentication noise detected.'
      },
      {
        key: 'stale',
        severity: staleActiveCount > 0 ? 'warning' : 'ok',
        title: 'Long-running active sessions',
        value: staleActiveCount,
        hint: staleActiveCount > 0 ? 'Consider reviewing or rotating long-lived sessions.' : 'All active sessions are recent.'
      },
      {
        key: 'adminops',
        severity: adminOps24h >= 10 ? 'warning' : 'ok',
        title: 'Admin changes (24h)',
        value: adminOps24h,
        hint: 'User/resource changes tracked for governance and forensics.'
      },
      {
        key: '2fa',
        severity: totpEnabled ? 'ok' : 'warning',
        title: 'MFA posture',
        value: totpEnabled ? 'enabled' : 'disabled',
        hint: totpEnabled ? 'Your account is protected with TOTP.' : 'Enable TOTP to strengthen operator authentication.'
      }
    ];
  }, [securityAuditItems, activeSessions, totpEnabled]);

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

  const formatRelativeDate = (value) => {
    const timestamp = Date.parse(value || '');
    if (!timestamp) return value || 'n/a';
    const diffSec = Math.floor((Date.now() - timestamp) / 1000);
    if (diffSec < 60) return 'just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  };

  const renderLogin = () => (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo-wrapper">
          <img src="/assets/logo-full-blue.png" alt="EndoriumFort" className="login-logo" />
        </div>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <h1>Sign in</h1>
          <button type="button" className="ghost icon-btn" title={darkMode ? 'Light mode' : 'Dark mode'} onClick={toggleDarkMode}>
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>
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
          <img src="/assets/logo-icon-dark.png" alt="EndoriumFort" className="brand-logo" />
          <div>
            <h1>Admin Console</h1>
            <p>Govern users, resources, and role-based permissions.</p>
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

      {canManagePlatform && stats && (
        <section className="stats-grid reveal" style={{ marginBottom: '1rem' }}>
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

      {!canManagePlatform ? (
        <div className="panel reveal">
          <h3>Platform admin access required</h3>
          <p className="muted">Sign in with the Platform Admin role to manage users and resources.</p>
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
              <label
                className="full"
                style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}
              >
                <input
                  name="requireAccessJustification"
                  type="checkbox"
                  checked={!!resourceForm.requireAccessJustification}
                  onChange={onResourceFieldChange}
                  style={{ width: 'auto' }}
                />
                Require reason popup before connect
              </label>
              <label
                className="full"
                style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}
              >
                <input
                  name="requireDualApproval"
                  type="checkbox"
                  checked={!!resourceForm.requireDualApproval}
                  onChange={onResourceFieldChange}
                  style={{ width: 'auto' }}
                />
                Require dual approval before session start
              </label>
              <label
                className="full"
                style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}
              >
                <input
                  name="enableCommandGuard"
                  type="checkbox"
                  checked={!!resourceForm.enableCommandGuard}
                  onChange={onResourceFieldChange}
                  style={{ width: 'auto' }}
                />
                Enable SSH command guard
              </label>
              <label
                className="full"
                style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}
              >
                <input
                  name="adaptiveAccessPolicy"
                  type="checkbox"
                  checked={!!resourceForm.adaptiveAccessPolicy}
                  onChange={onResourceFieldChange}
                  style={{ width: 'auto' }}
                />
                Adaptive policy (extra controls by risk)
              </label>
              <label className="full">
                Risk level
                <select
                  name="riskLevel"
                  value={resourceForm.riskLevel}
                  onChange={onResourceFieldChange}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
              <div className="resource-actions">
                <button type="submit">
                  {savingResource
                    ? (editingResourceId ? 'Updating...' : 'Creating...')
                    : (editingResourceId ? 'Update' : 'Create') + ' resource'}
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
                        sshPassword: '',
                        requireAccessJustification: false,
                        requireDualApproval: false,
                        enableCommandGuard: false,
                        adaptiveAccessPolicy: false,
                        riskLevel: 'low'
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
                      {resource.requireAccessJustification && (
                        <p className="muted">Reason popup required</p>
                      )}
                      {resource.requireDualApproval && (
                        <p className="muted">Dual approval required</p>
                      )}
                      {resource.enableCommandGuard && (
                        <p className="muted">Command guard enabled</p>
                      )}
                      {resource.adaptiveAccessPolicy && (
                        <p className="muted">Adaptive policy ({resource.riskLevel || 'low'})</p>
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
                <h3>Access Requests</h3>
                <p>Dual-control queue and user requests.</p>
              </div>
              {loadingAccessRequests && <span className="pill loading">loading</span>}
            </div>
            {accessRequestError && <p className="error">{accessRequestError}</p>}
            <div className="resource-list">
              {accessRequests.length ? (
                accessRequests.map((request) => (
                  <article className="resource-row" key={request.id}>
                    <div>
                      <h4>
                        #{request.id} {request.resourceName || `Resource ${request.resourceId}`}
                      </h4>
                      <p className="muted">
                        {request.requester} • {request.status} • {request.createdAt}
                      </p>
                      {request.justification && (
                        <p className="muted">{request.justification}</p>
                      )}
                      {request.ticketId && (
                        <p className="muted">Ticket: {request.ticketId}</p>
                      )}
                    </div>
                    {canManagePlatform && request.status === 'pending' && (
                      <div className="resource-actions">
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => onApproveAccessRequest(request.id)}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="ghost"
                          onClick={() => onDenyAccessRequest(request.id)}
                        >
                          Deny
                        </button>
                      </div>
                    )}
                  </article>
                ))
              ) : (
                <p className="muted">No access requests yet.</p>
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
                  <option value="operator">Session Operator</option>
                  <option value="admin">Platform Admin</option>
                  <option value="auditor">Security Auditor</option>
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
                      <p className="muted">Role: {roleLabel(user.role)}</p>
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

          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>RBAC Blueprint</h3>
                <p>Operational role model and expected permissions.</p>
              </div>
            </div>
            <div className="rbac-grid">
              {ROLE_BLUEPRINTS.map((role) => (
                <article className="rbac-card" key={role.id}>
                  <h4>{role.label}</h4>
                  <p className="muted">{role.description}</p>
                  <ul>
                    {role.permissions.map((permission) => (
                      <li key={`${role.id}-${permission}`}>{permission}</li>
                    ))}
                  </ul>
                </article>
              ))}
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
          <img src="/assets/logo-icon-dark.png" alt="EndoriumFort" className="brand-logo" />
          <div>
            <h1>WebBastion Console</h1>
            <p>Minimal access console for SSH sessions and live supervision.</p>
          </div>
        </div>
        <div className="top-actions">
          <div className="health">
            <span className={`pill ${status}`}>{status}</span>
            <span className="detail">{detail}</span>
            <span className="pill monitor">{roleName}</span>
          </div>
          <div className="nav-actions">
            {canManagePlatform && (
              <button
                type="button"
                className="secondary"
                onClick={() => navigate('/admin')}
              >
                Admin
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

      <section className="mission-board reveal" aria-label="Mission board navigation">
        <div className="mission-headline">
          <div>
            <p className="workflow-kicker">Access Workspace</p>
            <h3>Operate Without Context Switching</h3>
            <p>Open a resource and access it directly on this page. No dashboard detours.</p>
          </div>
          <div className="mission-headline-actions">
            <button type="button" className="ghost" onClick={onQuickRefresh} disabled={quickRefreshing}>
              {quickRefreshing ? 'Refreshing...' : 'Refresh data'}
            </button>
          </div>
        </div>

        <div className="mission-grid">
          {missionBoardEntries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={mainTab === entry.id ? 'mission-card active' : 'mission-card'}
              onClick={() => setMainTab(entry.id)}
            >
              <span className="mission-stage">{entry.stage}</span>
              <strong>{entry.title}</strong>
              <p>{entry.hint}</p>
              <span className="mission-shortcut">{entry.shortcut}</span>
            </button>
          ))}
        </div>

        <p className="muted">{tabGuide.focus}</p>
      </section>

      {/* ── Dashboard Stats ── */}
      {false && mainTab === 'overview' && stats && (
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

      {false && mainTab === 'overview' && (
      <section className="ops-grid">
        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Security center</h3>
              <p>Live posture and anomaly hints from audit and session activity.</p>
            </div>
            <div className="status-row">
              {canViewAudit ? (
                <span className={`pill ${loadingSecurityAudit ? 'loading' : 'ok'}`}>
                  {loadingSecurityAudit ? 'syncing' : `${securityAuditItems.length} feed items`}
                </span>
              ) : (
                <span className="pill loading">operator scope</span>
              )}
            </div>
          </div>
          <div className="security-alert-grid">
            {securityAlerts.map((alert) => (
              <article className={`security-alert ${alert.severity}`} key={alert.key}>
                <div className="security-alert-head">
                  <h4>{alert.title}</h4>
                  <span>{alert.value}</span>
                </div>
                <p className="muted">{alert.hint}</p>
              </article>
            ))}
          </div>
          <div className="security-actions">
            <button type="button" className="secondary" onClick={() => openAudit()}>
              Investigate in audit
            </button>
            {!totpEnabled && canManagePlatform && (
              <button type="button" className="ghost" onClick={() => navigate('/admin')}>
                Configure MFA
              </button>
            )}
          </div>
          {securityAuditError && <p className="error">{securityAuditError}</p>}
        </div>

        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>Recent sessions</h3>
              <p>Last opened sessions, prioritized for fast intervention.</p>
            </div>
            <span className="pill ok">{recentSessions.length} shown</span>
          </div>
          <div className="recent-session-list">
            {recentSessions.length ? (
              recentSessions.map((session) => (
                <article className="recent-session-item" key={`recent-${session.id}`}>
                  <div>
                    <h4>#{session.id} {session.user} -&gt; {session.target}</h4>
                    <p className="muted">{session.protocol}:{session.port} - opened {formatRelativeDate(session.createdAt)}</p>
                  </div>
                  <div className="recent-session-actions">
                    <span className={`pill ${session.status}`}>{session.status}</span>
                    {session.status === 'active' ? (
                      <button type="button" className="ghost" onClick={() => onTerminate(session.id)}>Terminate</button>
                    ) : (
                      <button type="button" className="ghost" onClick={() => openAudit(session.id)}>Audit</button>
                    )}
                  </div>
                </article>
              ))
            ) : (
              <p className="muted">No sessions yet.</p>
            )}
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

      {(mainTab === 'sessions' || mainTab === 'audit') && (
      <section className="main-grid">
        {mainTab === 'sessions' && (
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

          {canManagePlatform && (
            <div style={{ marginBottom: '1rem' }}>
              <div className="panel-header" style={{ marginBottom: '0.7rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem' }}>Pending Approvals</h3>
                  <p>Latest dual-control requests awaiting admin action.</p>
                </div>
                <span className={`pill ${pendingAccessApprovals.length ? 'loading' : 'ok'}`}>
                  {pendingAccessApprovals.length} pending
                </span>
              </div>
              {accessRequestError && <p className="error">{accessRequestError}</p>}
              <div className="resource-list">
                {pendingAccessApprovals.length ? (
                  pendingAccessApprovals.map((request) => (
                    <article className="resource-row" key={`pending-req-${request.id}`}>
                      <div>
                        <h4>
                          #{request.id} {request.resourceName || `Resource ${request.resourceId}`}
                        </h4>
                        <p className="muted">
                          {request.requester} • {request.createdAt}
                        </p>
                        {request.justification && <p className="muted">{request.justification}</p>}
                      </div>
                      <div className="resource-actions">
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => onApproveAccessRequest(request.id)}
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="ghost"
                          onClick={() => onDenyAccessRequest(request.id)}
                        >
                          Deny
                        </button>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="muted">No pending approvals.</p>
                )}
              </div>
            </div>
          )}

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
                    disabled={session.status !== 'active' || !canOperateSessions}
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
                  {canViewAudit && (
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
                    disabled={session.status !== 'active' || !canOperateSessions}
                  >
                    Open live
                  </button>
                  {canViewAudit &&
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
        )}
        {mainTab === 'audit' && (
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
              <button type="button" className="ghost" onClick={() => setAuditFilter(null)}>
                Clear view
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
            {!canViewAudit && (
              <p className="muted">Sign in with Security Auditor or Platform Admin role.</p>
            )}
            {canViewAudit && (
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
      )}

      {/* Recordings panel */}
      {mainTab === 'recordings' && canViewRecordings && (
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
            <button type="button" className="ghost" onClick={closePlayer}>Reset player</button>
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

      {mainTab === 'sessions' && (
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
      )}

      {mainTab === 'sessions' && inlineWebResource && (
      <section className="panel reveal" style={{ marginBottom: '24px' }}>
        <div className="panel-header">
          <div>
            <h3>Embedded Web Access</h3>
            <p>
              {inlineWebResource.name} - {inlineWebResource.protocol} {inlineWebResource.target}:{inlineWebResource.port}
            </p>
          </div>
          <div className="resource-actions">
            <button
              type="button"
              className="ghost"
              onClick={() => setInlineWebResource(null)}
            >
              Close
            </button>
          </div>
        </div>
        <iframe
          title={`resource-${inlineWebResource.id}`}
          src={`/proxy/${inlineWebResource.id}/`}
          className="proxy-iframe"
          style={{ minHeight: '520px', borderRadius: '12px', border: '1px solid var(--stroke)' }}
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals allow-top-navigation-by-user-activation"
        />
      </section>
      )}

      {/* Shadow session panel */}
      {mainTab === 'sessions' && shadowSession && (
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

      {accessPromptResource && (
        <div
          className="modal-overlay"
          onClick={() => {
            setAccessPromptResource(null);
            setAccessPromptMode('connect');
          }}
        >
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>
              {accessPromptMode === 'request'
                ? 'Approval Request Required'
                : 'Connection Justification Required'}
            </h3>
            <p className="muted" style={{ marginTop: 0 }}>
              {accessPromptMode === 'request'
                ? `${accessPromptResource.name} requires an approval workflow before session start.`
                : `${accessPromptResource.name} requires an access reason before opening the session.`}
            </p>
            <form onSubmit={onSubmitAccessPrompt}>
              <label>
                Access reason
                <input
                  type="text"
                  value={accessPromptReason}
                  onChange={(event) => setAccessPromptReason(event.target.value)}
                  placeholder="Describe why you need this access"
                  required
                />
              </label>
              <label>
                Ticket / Change ID (optional)
                <input
                  type="text"
                  value={accessPromptTicketId}
                  onChange={(event) => setAccessPromptTicketId(event.target.value)}
                  placeholder="INC-1234 / CHG-5678"
                />
              </label>
              <div style={{ display: 'flex', gap: '0.8rem', marginTop: '0.8rem' }}>
                <button type="submit">
                  {accessPromptMode === 'request' ? 'Submit request' : 'Continue'}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    setAccessPromptResource(null);
                    setAccessPromptReason('');
                    setAccessPromptTicketId('');
                    setAccessPromptMode('connect');
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
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
  return renderMain();
}

import React, { Suspense, lazy, useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import QRCode from 'qrcode';
import {
  changePassword,
  createResource,
  createSession,
  deleteResource,
  deleteUser,
  disable2FA,
  fetchBootstrapStatus,
  fetchAudit,
  fetchHealth,
  fetchRecordingCast,
  fetchRecordings,
  fetchContainmentStatus,
  fetchActiveSecurityIncident,
  openSecurityIncident,
  closeSecurityIncident,
  reportSecurityIncidentEscalation,
  fetchSecurityAlerts,
  fetchSessionDna,
  issueEphemeralCredential,
  consumeEphemeralCredential,
  previewSessionRisk,
  fetchResources,
  fetchSessions,
  fetchStats,
  fetchUsers,
  get2FAStatus,
  login,
  logout,
  startOidcSso,
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
  createAccessPolicy,
  createAccessProfile,
  approveAccessRequest,
  denyAccessRequest,
  deleteAccessPolicy,
  deleteAccessProfile,
  setContainmentMode,
  fetchRelays,
  fetchRelayConfig,
  createRelayEnrollmentToken,
  createRelayCertificate,
  assignRelayToResource,
  clearRelayForResource,
  fetchRelayResolution,
  beginWebAuthnRegistration,
  verifyWebAuthnRegistration,
  deleteWebAuthnCredential,
  setMfaPreference,
  fetchAccessPolicies,
  fetchAccessProfiles,
  fetchAccessGrants,
  fetchSessionEvidencePack,
  getUserAccessProfiles,
  grantAccessProfile,
  revokeAccessProfile,
  updateAccessPolicy,
  updateAccessProfile,
  fetchDirectoryProviders,
  fetchLdapConfig,
  fetchSsoProviders,
  fetchSsoConfig,
  testLdapBind,
  fetchScimServiceProviderConfig,
  fetchScimUsers,
  fetchScimGroups,
  patchScimUser,
  fetchItsmProviders,
  verifyItsmTicket,
  fetchSiemChannels,
  forwardSiemEvent,
  fetchClusterStatus,
  fetchClusterConfig,
  removeClusterPeer
} from './api.js';
import { describeAccessOutcome, describeResourcePolicy, normalizeRiskLevel } from './accessPolicy.js';
import AdminSectionNav from './components/admin/AdminSectionNav.jsx';
import VncViewerModal from './components/sessions/VncViewerModal.jsx';
import { EmptyState, InlineAlert, MetricTile, SectionCard, StatusBadge } from './components/ui/primitives.jsx';
import { useI18n } from './i18n.jsx';

const RecordingsPanel = lazy(() => import('./components/operator/RecordingsPanel.jsx'));

const normalizeRole = (role) => {
  const value = String(role || '').toLowerCase();
  if (value === 'platform_admin' || value === 'access_admin') return 'admin';
  if (value === 'session_operator') return 'operator';
  if (value === 'security_auditor' || value === 'security_analyst') return 'auditor';
  return value || 'operator';
};

const roleLabel = (role, t) => {
  const mapped = normalizeRole(role);
  if (!t) return mapped;
  const label = t(`roles.${mapped}.label`);
  return label !== `roles.${mapped}.label` ? label : mapped;
};

const isWebAuthnSupported = () =>
  typeof window !== 'undefined' &&
  typeof window.PublicKeyCredential !== 'undefined' &&
  typeof navigator !== 'undefined' &&
  !!navigator.credentials?.create &&
  !!navigator.credentials?.get;

const decodeBase64Url = (value) => {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const encodeBase64Url = (value) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value || []);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const serializeAuthenticatorTransports = (response) => {
  if (!response || typeof response.getTransports !== 'function') return [];
  try {
    const transports = response.getTransports();
    return Array.isArray(transports) ? transports : [];
  } catch (_) {
    return [];
  }
};

const createBrowserPasskey = async (options) => {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not available in this browser.');
  }
  const publicKey = {
    ...options.publicKey,
    challenge: decodeBase64Url(options.publicKey.challenge),
    user: {
      ...options.publicKey.user,
      id: decodeBase64Url(options.publicKey.user.id)
    },
    excludeCredentials: (options.publicKey.excludeCredentials || []).map((item) => ({
      ...item,
      id: decodeBase64Url(item.id)
    }))
  };
  const credential = await navigator.credentials.create({ publicKey });
  if (!credential || !credential.response || typeof credential.response.getPublicKey !== 'function') {
    throw new Error('This browser did not return a usable WebAuthn public key.');
  }
  const publicKeyBuffer = credential.response.getPublicKey();
  const authenticatorData = credential.response.getAuthenticatorData?.();
  if (!publicKeyBuffer || !authenticatorData) {
    throw new Error('Unable to extract WebAuthn registration data from this browser.');
  }
  return {
    credentialId: credential.id,
    publicKey: encodeBase64Url(new Uint8Array(publicKeyBuffer)),
    algorithm: credential.response.getPublicKeyAlgorithm?.() || 0,
    authenticatorData: encodeBase64Url(new Uint8Array(authenticatorData)),
    clientDataJSON: encodeBase64Url(new Uint8Array(credential.response.clientDataJSON)),
    transports: serializeAuthenticatorTransports(credential.response)
  };
};

const getBrowserPasskeyAssertion = async (options) => {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not available in this browser.');
  }
  const publicKey = {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({
      ...item,
      id: decodeBase64Url(item.id)
    }))
  };
  const credential = await navigator.credentials.get({ publicKey });
  if (!credential || !credential.response) {
    throw new Error('No passkey assertion was returned by the browser.');
  }
  return {
    credentialId: credential.id,
    authenticatorData: encodeBase64Url(new Uint8Array(credential.response.authenticatorData)),
    clientDataJSON: encodeBase64Url(new Uint8Array(credential.response.clientDataJSON)),
    signature: encodeBase64Url(new Uint8Array(credential.response.signature))
  };
};

const CAPABILITY_PERMISSION_MAP = {
  manageResources: ['resources.manage'],
  viewAudit: ['audit.read'],
  viewRecordings: ['recordings.read'],
  operateSessions: ['sessions.create', 'sessions.read'],
  viewStats: ['stats.read']
};

const hasRoleCapabilityFallback = (role, capability) => {
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

const hasCapability = (role, permissions, capability) => {
  const required = CAPABILITY_PERMISSION_MAP[capability] || [];
  if (Array.isArray(permissions) && permissions.length) {
    return required.some((permission) => permissions.includes(permission) || permissions.includes('*'));
  }
  return hasRoleCapabilityFallback(role, capability);
};

const LIVE_ALERT_SEVERITY_WEIGHT = {
  critical: 3,
  warning: 2,
  ok: 1
};

const LIVE_ALERT_COOLDOWN_MS = {
  critical: 0,
  warning: 45000,
  ok: 120000
};

const LIVE_ALERT_PROFILES = {
  strict: {
    cooldownMultiplier: 1.8,
    maxVisible: { critical: 2, warning: 2, ok: 1, total: 4 }
  },
  normal: {
    cooldownMultiplier: 1,
    maxVisible: { critical: 2, warning: 3, ok: 1, total: 5 }
  },
  permissive: {
    cooldownMultiplier: 0.55,
    maxVisible: { critical: 3, warning: 4, ok: 2, total: 7 }
  }
};

const LIVE_ALERT_PROFILE_LABEL = {
  strict: 'Strict',
  normal: 'Normal',
  permissive: 'Permissive'
};

const compareLiveAlertPriority = (left, right) => {
  const severityDelta =
    (LIVE_ALERT_SEVERITY_WEIGHT[right.severity] || 0) -
    (LIVE_ALERT_SEVERITY_WEIGHT[left.severity] || 0);
  if (severityDelta !== 0) return severityDelta;
  const rightTime = Date.parse(right.createdAt || '') || 0;
  const leftTime = Date.parse(left.createdAt || '') || 0;
  return rightTime - leftTime;
};

const capLiveAlertsBySeverity = (alerts, maxVisible) => {
  const capped = [];
  const counts = { critical: 0, warning: 0, ok: 0 };
  for (const item of alerts) {
    const severity = item.severity === 'critical' || item.severity === 'ok'
      ? item.severity
      : 'warning';
    const severityLimit = maxVisible[severity] ?? 1;
    if (counts[severity] >= severityLimit) {
      continue;
    }
    if (capped.length >= (maxVisible.total ?? 5)) {
      break;
    }
    counts[severity] += 1;
    capped.push({ ...item, severity });
  }
  return capped;
};

const extractSessionIdFromAuditItem = (item) => {
  if (!item?.payloadIsJson || !item?.payloadRaw) return null;
  try {
    const payload = JSON.parse(item.payloadRaw);
    const sessionId = Number(payload?.sessionId || 0);
    return Number.isFinite(sessionId) && sessionId > 0 ? sessionId : null;
  } catch (_) {
    return null;
  }
};

const DEFAULT_SSH_SNIPPETS = [
  { id: 'health', labelKey: 'Health Snapshot', command: 'whoami && hostname && uptime' },
  { id: 'net', labelKey: 'Network Quick Check', command: 'ip a && ss -tulpen | head -n 30' },
  { id: 'disk', labelKey: 'Disk Pressure', command: 'df -h && du -sh /var/log 2>/dev/null' },
  { id: 'proc', labelKey: 'Top Processes', command: 'ps aux --sort=-%cpu | head -n 15' }
];

const ACCESS_PLAYBOOK_STORAGE_KEY = 'endoriumfort_access_playbooks';
const SESSION_WATCHLIST_STORAGE_KEY = 'endoriumfort_session_watchlist';

const clampInteger = (value, fallback, min, max) => {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
};

export default function App() {
  const { locale, setLocale, t, raw } = useI18n();
  const [status, setStatus] = useState('loading');
  const [detail, setDetail] = useState('');
  const [auth, setAuth] = useState(() => {
    try {
      const saved = localStorage.getItem('endoriumfort_auth');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.token) {
          setAuthToken(parsed.token);
          return {
            user: parsed.user || '',
            password: '',
            role: normalizeRole(parsed.role),
            token: parsed.token,
            permissions: Array.isArray(parsed.permissions) ? parsed.permissions : []
          };
        }
      }
    } catch (_) {}
    return { user: '', password: '', role: 'operator', token: '', permissions: [] };
  });
  const [authError, setAuthError] = useState('');
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [sessionError, setSessionError] = useState('');
  const [activeTerminalSession, setActiveTerminalSession] = useState(null);
  const [terminalStatus, setTerminalStatus] = useState('idle');
  const [terminalError, setTerminalError] = useState('');
  const [terminalInfo, setTerminalInfo] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [snippetLabel, setSnippetLabel] = useState('');
  const [snippetCommand, setSnippetCommand] = useState('');
  const [customSnippets, setCustomSnippets] = useState(() => {
    try {
      const raw = localStorage.getItem('endoriumfort_custom_ssh_snippets');
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  });
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
    tunnelTicketRateLimitMaxAttempts: '0',
    description: '',
    imageUrl: '',
    imageData: '', // base64 locale
    tagsCsv: '',
    credentialSource: 'vaulted',
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
    role: 'operator',
    forcePasswordRotation: false
  });
  const [editingUserId, setEditingUserId] = useState(null);
  const [selectedUserForAccessScope, setSelectedUserForAccessScope] = useState(null);
  const [userResourceScope, setUserResourceScope] = useState([]);
  const [userAccessProfiles, setUserAccessProfiles] = useState([]);
  const [loadingAccessScope, setLoadingAccessScope] = useState(false);
  const [accessScopeError, setAccessScopeError] = useState('');
  const [accessPolicies, setAccessPolicies] = useState([]);
  const [loadingAccessPolicies, setLoadingAccessPolicies] = useState(false);
  const [accessPolicyError, setAccessPolicyError] = useState('');
  const [editingAccessPolicyId, setEditingAccessPolicyId] = useState(null);
  const [accessPolicyForm, setAccessPolicyForm] = useState({
    name: '',
    description: '',
    identityPattern: '',
    groupName: '',
    role: '',
    resourceTagsCsv: '',
    riskLevel: 'any',
    ticketRequired: false,
    requireJustification: false,
    approvalMode: 'inherit',
    mfaRequirement: 'any',
    timeWindow: 'any',
    maxDurationSeconds: '3600',
    routingConstraint: 'any',
    enabled: true
  });
  const [accessProfiles, setAccessProfiles] = useState([]);
  const [loadingAccessProfiles, setLoadingAccessProfiles] = useState(false);
  const [accessProfileError, setAccessProfileError] = useState('');
  const [editingAccessProfileId, setEditingAccessProfileId] = useState(null);
  const [accessProfileForm, setAccessProfileForm] = useState({
    name: '',
    description: '',
    resourceTagsCsv: '',
    resourceIdsCsv: '',
    policyId: '0'
  });
  const [accessGrants, setAccessGrants] = useState([]);
  const [loadingAccessGrants, setLoadingAccessGrants] = useState(false);
  const [accessGrantError, setAccessGrantError] = useState('');
  const [enterpriseLoading, setEnterpriseLoading] = useState(false);
  const [enterpriseError, setEnterpriseError] = useState('');
  const [enterpriseDirectoryProviders, setEnterpriseDirectoryProviders] = useState([]);
  const [enterpriseLdapConfig, setEnterpriseLdapConfig] = useState(null);
  const [enterpriseLdapTestUsername, setEnterpriseLdapTestUsername] = useState('');
  const [enterpriseLdapTestPassword, setEnterpriseLdapTestPassword] = useState('');
  const [enterpriseLdapTesting, setEnterpriseLdapTesting] = useState(false);
  const [enterpriseLdapTestResult, setEnterpriseLdapTestResult] = useState(null);
  const [enterpriseSsoProviders, setEnterpriseSsoProviders] = useState([]);
  const [enterpriseSsoProvider, setEnterpriseSsoProvider] = useState('');
  const [enterpriseSsoConfig, setEnterpriseSsoConfig] = useState(null);
  const [enterpriseScimConfig, setEnterpriseScimConfig] = useState(null);
  const [enterpriseScimUsers, setEnterpriseScimUsers] = useState([]);
  const [enterpriseScimGroups, setEnterpriseScimGroups] = useState([]);
  const [enterpriseScimMeta, setEnterpriseScimMeta] = useState({
    users: { totalResults: 0, startIndex: 1, itemsPerPage: 0 },
    groups: { totalResults: 0, startIndex: 1, itemsPerPage: 0 }
  });
  const [enterpriseScimFilter, setEnterpriseScimFilter] = useState('');
  const [enterpriseScimStartIndex, setEnterpriseScimStartIndex] = useState('1');
  const [enterpriseScimCount, setEnterpriseScimCount] = useState('20');
  const [enterpriseScimLoading, setEnterpriseScimLoading] = useState(false);
  const [enterpriseScimError, setEnterpriseScimError] = useState('');
  const [enterpriseScimPatchId, setEnterpriseScimPatchId] = useState('');
  const [enterpriseScimPatchUsername, setEnterpriseScimPatchUsername] = useState('');
  const [enterpriseScimPatchRole, setEnterpriseScimPatchRole] = useState('');
  const [enterpriseScimPatchActive, setEnterpriseScimPatchActive] = useState('unchanged');
  const [enterpriseScimPatchLoading, setEnterpriseScimPatchLoading] = useState(false);
  const [enterpriseScimPatchResult, setEnterpriseScimPatchResult] = useState('');
  const [enterpriseItsmProviders, setEnterpriseItsmProviders] = useState([]);
  const [enterpriseItsmProvider, setEnterpriseItsmProvider] = useState('servicenow');
  const [enterpriseItsmTicketId, setEnterpriseItsmTicketId] = useState('');
  const [enterpriseItsmFailMode, setEnterpriseItsmFailMode] = useState('fail-closed');
  const [enterpriseItsmUnavailable, setEnterpriseItsmUnavailable] = useState(false);
  const [enterpriseItsmLoading, setEnterpriseItsmLoading] = useState(false);
  const [enterpriseItsmResult, setEnterpriseItsmResult] = useState(null);
  const [enterpriseSiemChannels, setEnterpriseSiemChannels] = useState([]);
  const [enterpriseSiemChannel, setEnterpriseSiemChannel] = useState('json_webhook');
  const [enterpriseSiemEventType, setEnterpriseSiemEventType] = useState('security.event.test');
  const [enterpriseSiemDeliveryMode, setEnterpriseSiemDeliveryMode] = useState('fail-open');
  const [enterpriseSiemSimulateFailure, setEnterpriseSiemSimulateFailure] = useState(false);
  const [enterpriseSiemLoading, setEnterpriseSiemLoading] = useState(false);
  const [enterpriseSiemResult, setEnterpriseSiemResult] = useState(null);
  const [enterpriseClusterStatus, setEnterpriseClusterStatus] = useState(null);
  const [enterpriseClusterConfig, setEnterpriseClusterConfig] = useState(null);
  const [enterpriseClusterPeerBusy, setEnterpriseClusterPeerBusy] = useState('');
  const [enterpriseClusterPeerMessage, setEnterpriseClusterPeerMessage] = useState('');
  const [sessionEvidencePack, setSessionEvidencePack] = useState(null);
  const [sessionEvidenceLoading, setSessionEvidenceLoading] = useState(false);
  const [sessionEvidenceError, setSessionEvidenceError] = useState('');
  const [route, setRoute] = useState(() =>
    window.location.pathname ? window.location.pathname : '/'
  );
  const [adminSection, setAdminSection] = useState('resources');
  const [mainTab, setMainTab] = useState('sessions');
  const [inlineWebResource, setInlineWebResource] = useState(null);
  const [vncViewerSession, setVncViewerSession] = useState(null);
  const [accessPromptResource, setAccessPromptResource] = useState(null);
  const [accessPromptReason, setAccessPromptReason] = useState('');
  const [accessPromptTicketId, setAccessPromptTicketId] = useState('');
  const [accessPromptPurpose, setAccessPromptPurpose] = useState('');
  const [accessPromptPurposeEvidence, setAccessPromptPurposeEvidence] = useState('');
  const [accessPromptMode, setAccessPromptMode] = useState('connect');
  const [accessPlaybooks, setAccessPlaybooks] = useState(() => {
    try {
      const raw = localStorage.getItem(ACCESS_PLAYBOOK_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  });
  const [watchedSessionIds, setWatchedSessionIds] = useState(() => {
    try {
      const raw = localStorage.getItem(SESSION_WATCHLIST_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.map((item) => Number(item)).filter((id) => id > 0) : [];
    } catch (_) {
      return [];
    }
  });
  const [watchlistAlerts, setWatchlistAlerts] = useState([]);
  const [riskPreview, setRiskPreview] = useState(null);
  const [riskPreviewLoading, setRiskPreviewLoading] = useState(false);
  const [riskPreviewError, setRiskPreviewError] = useState('');
  const [sessionDna, setSessionDna] = useState(null);
  const [sessionDnaLoading, setSessionDnaLoading] = useState(false);
  const [sessionDnaError, setSessionDnaError] = useState('');
  const [accessRequests, setAccessRequests] = useState([]);
  const [loadingAccessRequests, setLoadingAccessRequests] = useState(false);
  const [accessRequestError, setAccessRequestError] = useState('');
  const [relays, setRelays] = useState([]);
  const [loadingRelays, setLoadingRelays] = useState(false);
  const [relayError, setRelayError] = useState('');
  const [relayConfig, setRelayConfig] = useState({
    enrollmentEnabled: false,
    certificateRequired: true,
    certificateTtlSeconds: 2592000,
    enrollmentTokenTtlSeconds: 600,
    tokenTtlSeconds: 86400,
    heartbeatStaleSeconds: 90
  });
  const [relayCertificate, setRelayCertificate] = useState('');
  const [relayCertificateId, setRelayCertificateId] = useState('');
  const [relayCertificateExpiresAt, setRelayCertificateExpiresAt] = useState('');
  const [issuingRelayCertificate, setIssuingRelayCertificate] = useState(false);
  const [relayCertificateCopyStatus, setRelayCertificateCopyStatus] = useState('');
  const [relayEnrollmentToken, setRelayEnrollmentToken] = useState('');
  const [relayEnrollmentTokenExpiresAt, setRelayEnrollmentTokenExpiresAt] = useState('');
  const [issuingRelayEnrollmentToken, setIssuingRelayEnrollmentToken] = useState(false);
  const [relayEnrollmentCopyStatus, setRelayEnrollmentCopyStatus] = useState('');
  const [showRelayManualBootstrap, setShowRelayManualBootstrap] = useState(false);
  const [relayBindings, setRelayBindings] = useState({});
  const [sessionRelayHints, setSessionRelayHints] = useState({});
  const [relayAssignBusyResourceId, setRelayAssignBusyResourceId] = useState(0);
  const [relayAssignOnlineOnly, setRelayAssignOnlineOnly] = useState(true);
  // 2FA state
  const [twoFARequired, setTwoFARequired] = useState(false);
  const [availableMfaMethods, setAvailableMfaMethods] = useState([]);
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState(null);
  const [totpSetupCode, setTotpSetupCode] = useState('');
  const [totpError, setTotpError] = useState('');
  const [totpDisableCode, setTotpDisableCode] = useState('');
  const [totpCopyStatus, setTotpCopyStatus] = useState('');
  const [totpQrDataUrl, setTotpQrDataUrl] = useState('');
  const [webauthnEnabled, setWebauthnEnabled] = useState(false);
  const [webauthnCredentials, setWebauthnCredentials] = useState([]);
  const [webauthnLoginOptions, setWebauthnLoginOptions] = useState(null);
  const [webauthnBusy, setWebauthnBusy] = useState(false);
  const [webauthnLabel, setWebauthnLabel] = useState('');
  const [preferredMfaMethod, setPreferredMfaMethod] = useState('any');
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
  const [liveSecurityAlerts, setLiveSecurityAlerts] = useState([]);
  const [liveSecurityIncident, setLiveSecurityIncident] = useState(null);
  const [containmentStatus, setContainmentStatus] = useState({
    enabled: false,
    updatedAt: '',
    updatedBy: '',
    reason: ''
  });
  const [activeSecurityIncident, setActiveSecurityIncident] = useState({
    active: false,
    incident: null
  });
  const [incidentCaseBusy, setIncidentCaseBusy] = useState(false);
  const [containmentBusy, setContainmentBusy] = useState(false);
  const [incidentTerminateConfirmOpen, setIncidentTerminateConfirmOpen] = useState(false);
  const [incidentTerminateBusy, setIncidentTerminateBusy] = useState(false);
  const [liveAlertProfile, setLiveAlertProfile] = useState(() => {
    try {
      const saved = localStorage.getItem('endoriumfort_live_alert_profile');
      return saved && LIVE_ALERT_PROFILES[saved] ? saved : 'normal';
    } catch (_) {
      return 'normal';
    }
  });
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
  const agentLaunchTimeoutRef = useRef(null);
  const agentLaunchCleanupRef = useRef(null);
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
  const [bootstrapState, setBootstrapState] = useState({
    required: false,
    passwordChangeRequired: false,
    mfaSetupRequired: false,
    totpEnabled: false,
    webauthnEnabled: false
  });
  // Token expiry
  const [tokenExpiresAt, setTokenExpiresAt] = useState('');
  const terminalRef = useRef(null);
  const terminalInstanceRef = useRef(null);
  const fitAddonRef = useRef(null);
  const socketRef = useRef(null);
  const terminalInputListenerRef = useRef(null);
  const securityFeedBootstrappedRef = useRef(false);
  const lastSecurityAuditIdRef = useRef(0);
  const liveAlertCooldownByTypeRef = useRef({});
  const liveIncidentCriticalTimestampsRef = useRef([]);
  const liveIncidentCooldownUntilRef = useRef(0);
  const watchlistStatusRef = useRef({});

  const canManagePlatform = hasCapability(auth.role, auth.permissions, 'manageResources');
  const canViewAudit = hasCapability(auth.role, auth.permissions, 'viewAudit');
  const canViewRecordings = hasCapability(auth.role, auth.permissions, 'viewRecordings');
  const canOperateSessions = hasCapability(auth.role, auth.permissions, 'operateSessions');
  const roleName = roleLabel(auth.role, t);
  const activeLiveAlertProfile = LIVE_ALERT_PROFILES[liveAlertProfile] || LIVE_ALERT_PROFILES.normal;
  const containmentEnabled = !!containmentStatus.enabled;
  const bootstrapRequired = !!(auth.token && bootstrapState.required);
  const roleBlueprints = useMemo(() => ([
    {
      id: 'operator',
      label: t('roles.operator.label'),
      description: t('roles.operator.description'),
      permissions: raw('roles.operator.permissions') || []
    },
    {
      id: 'admin',
      label: t('roles.admin.label'),
      description: t('roles.admin.description'),
      permissions: raw('roles.admin.permissions') || []
    },
    {
      id: 'auditor',
      label: t('roles.auditor.label'),
      description: t('roles.auditor.description'),
      permissions: raw('roles.auditor.permissions') || []
    }
  ]), [raw, t]);

  useEffect(() => {
    try {
      localStorage.setItem('endoriumfort_live_alert_profile', liveAlertProfile);
    } catch (_) {}
  }, [liveAlertProfile]);

  useEffect(() => {
    try {
      localStorage.setItem('endoriumfort_custom_ssh_snippets', JSON.stringify(customSnippets));
    } catch (_) {}
  }, [customSnippets]);

  useEffect(() => {
    try {
      localStorage.setItem(ACCESS_PLAYBOOK_STORAGE_KEY, JSON.stringify(accessPlaybooks));
    } catch (_) {}
  }, [accessPlaybooks]);

  useEffect(() => {
    try {
      localStorage.setItem(SESSION_WATCHLIST_STORAGE_KEY, JSON.stringify(watchedSessionIds));
    } catch (_) {}
  }, [watchedSessionIds]);

  const currentAccessPlaybook = useMemo(() => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return null;
    return (
      accessPlaybooks.find((item) => Number(item.resourceId) === resourceId) || null
    );
  }, [accessPlaybooks, accessPromptResource]);

  const sshSnippetLibrary = useMemo(() => {
    const normalizedCustom = customSnippets
      .map((item) => ({
        id: String(item.id || ''),
        label: String(item.label || '').trim(),
        command: String(item.command || '').trim()
      }))
      .filter((item) => item.id && item.label && item.command)
      .map((item) => ({ ...item, custom: true }));
    return [
      ...DEFAULT_SSH_SNIPPETS.map((item) => ({ ...item, label: item.labelKey, custom: false })),
      ...normalizedCustom
    ];
  }, [customSnippets]);
  const tabGuide = useMemo(() => {
    const base = {
      overview: {
        title: t('app.overview'),
        hint: t('app.overviewHint'),
        focus: t('app.overviewFocus')
      },
      sessions: {
        title: t('app.sessions'),
        hint: t('app.sessionsHint'),
        focus: t('app.sessionsFocus')
      },
      audit: {
        title: t('app.audit'),
        hint: t('app.auditHint'),
        focus: t('app.auditFocus')
      },
      recordings: {
        title: t('app.recordings'),
        hint: t('app.recordingsHint'),
        focus: t('app.recordingsFocus')
      }
    };
    return base[mainTab] || base.overview;
  }, [mainTab, t]);

  const missionBoardEntries = useMemo(() => {
    const entries = [
      {
        id: 'sessions',
        stage: t('app.operate'),
        title: t('app.liveAccess'),
        shortcut: 'Alt+1',
        hint: t('app.openAndSupervise')
      },
      {
        id: 'audit',
        stage: t('app.trace'),
        title: t('app.investigation'),
        shortcut: 'Alt+2',
        hint: t('app.reviewEvents')
      },
      {
        id: 'recordings',
        stage: t('app.evidence'),
        title: t('app.replayVault'),
        shortcut: 'Alt+3',
        hint: t('app.replayRecordedSsh'),
        hidden: !canViewRecordings
      }
    ];

    return entries.filter((entry) => !entry.hidden);
  }, [canViewRecordings, t]);

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

  const relayInventorySummary = useMemo(() => {
    const online = relays.filter((item) => String(item.status).toLowerCase() === 'online').length;
    return {
      total: relays.length,
      online,
      offline: Math.max(0, relays.length - online)
    };
  }, [relays]);

  const adminSections = useMemo(() => {
    const adminsWithoutMfa = stats?.users?.adminsWithoutMfa || 0;
    const pendingRequests = accessRequests.filter((item) => item.status === 'pending').length;
    return [
      {
        id: 'resources',
        label: t('admin.resources'),
        hint: t('admin.inventoryAndPolicies'),
        badge: String(resources.length),
        badgeTone: loadingResources ? 'loading' : 'ok'
      },
      {
        id: 'users',
        label: t('admin.users'),
        hint: t('admin.accountsAndAccessScope'),
        badge: String(users.length),
        badgeTone: loadingUsers ? 'loading' : 'ok'
      },
      {
        id: 'routing',
        label: t('admin.routing'),
        hint: t('admin.relaysAndApprovals'),
        badge: pendingRequests ? t('admin.pendingCount', { count: pendingRequests }) : t('admin.onlineCount', { count: relayInventorySummary.online }),
        badgeTone: pendingRequests ? 'active' : 'ok'
      },
      {
        id: 'jit',
        label: 'JIT',
        hint: 'Policies, profiles and grants',
        badge: String(accessGrants.length),
        badgeTone: loadingAccessGrants ? 'loading' : 'ok'
      },
      {
        id: 'enterprise',
        label: 'Enterprise IAM',
        hint: 'LDAP/AD, SSO, SCIM, ITSM, SIEM',
        
        badge: String(
          enterpriseDirectoryProviders.length +
          enterpriseSsoProviders.length +
          enterpriseItsmProviders.length +
          enterpriseSiemChannels.length +
          (Number(enterpriseClusterStatus?.summary?.nodesTotal) || 0)
        ),
        badgeTone: enterpriseLoading ? 'loading' : 'ok'
      },
      {
        id: 'security',
        label: t('admin.security'),
        hint: t('admin.mfaAndPosture'),
        badge: adminsWithoutMfa ? t('admin.riskCount', { count: adminsWithoutMfa }) : t('admin.healthy'),
        badgeTone: adminsWithoutMfa ? 'loading' : 'ok'
      }
    ];
  }, [accessGrants.length, accessRequests, enterpriseClusterStatus, enterpriseDirectoryProviders.length, enterpriseItsmProviders.length, enterpriseLoading, enterpriseSiemChannels.length, enterpriseSsoProviders.length, loadingAccessGrants, loadingResources, loadingUsers, relayInventorySummary.online, resources.length, stats?.users?.adminsWithoutMfa, t, users.length]);

  const activeAdminSection = useMemo(
    () => adminSections.find((section) => section.id === adminSection) || null,
    [adminSection, adminSections]
  );

  const isRelayOnline = (relay) => String(relay?.status || '').toLowerCase() === 'online';

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
      setAuth((prev) => ({ ...prev, token: '', password: '', permissions: [] }));
      setAuthError(t('auth.sessionExpired'));
      setTokenExpiresAt('');
      setBootstrapState({
        required: false,
        passwordChangeRequired: false,
        mfaSetupRequired: false,
        totpEnabled: false,
        webauthnEnabled: false
      });
      setWebauthnEnabled(false);
      setWebauthnCredentials([]);
      setWebauthnLoginOptions(null);
      setAvailableMfaMethods([]);
      setPreferredMfaMethod('any');
      setAuthToken('');
      navigate('/login');
    };
    window.addEventListener('endoriumfort:unauthorized', onUnauthorized);
    return () => window.removeEventListener('endoriumfort:unauthorized', onUnauthorized);
  }, [t]);

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
      setAuthError(t('auth.sessionExpired'));
    }, remaining);
    return () => clearTimeout(timer);
  }, [tokenExpiresAt, auth.token, t]);

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
        setDetail(data.message || t('app.healthApiReachable'));
      })
      .catch(() => {
        if (!active) return;
        setStatus('offline');
        setDetail(t('app.healthStartBackend'));
      });
    return () => {
      active = false;
    };
  }, [t]);

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

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
      setAccessPolicies([]);
      setLoadingAccessPolicies(false);
      return;
    }
    let active = true;
    setLoadingAccessPolicies(true);
    fetchAccessPolicies()
      .then((data) => {
        if (!active) return;
        setAccessPolicies(Array.isArray(data.items) ? data.items : []);
        setAccessPolicyError('');
      })
      .catch((error) => {
        if (!active) return;
        setAccessPolicyError(error.message || 'Unable to load access policies');
      })
      .finally(() => {
        if (!active) return;
        setLoadingAccessPolicies(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, canManagePlatform]);

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
      setAccessProfiles([]);
      setLoadingAccessProfiles(false);
      return;
    }
    let active = true;
    setLoadingAccessProfiles(true);
    fetchAccessProfiles()
      .then((data) => {
        if (!active) return;
        setAccessProfiles(Array.isArray(data.items) ? data.items : []);
        setAccessProfileError('');
      })
      .catch((error) => {
        if (!active) return;
        setAccessProfileError(error.message || 'Unable to load access profiles');
      })
      .finally(() => {
        if (!active) return;
        setLoadingAccessProfiles(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token, canManagePlatform]);

  useEffect(() => {
    if (!auth.token) {
      setAccessGrants([]);
      setLoadingAccessGrants(false);
      return;
    }
    let active = true;
    setLoadingAccessGrants(true);
    fetchAccessGrants()
      .then((data) => {
        if (!active) return;
        setAccessGrants(Array.isArray(data.items) ? data.items : []);
        setAccessGrantError('');
      })
      .catch((error) => {
        if (!active) return;
        setAccessGrantError(error.message || 'Unable to load access grants');
      })
      .finally(() => {
        if (!active) return;
        setLoadingAccessGrants(false);
      });
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
      setRelays([]);
      setRelayError('');
      setLoadingRelays(false);
      return;
    }
    let active = true;
    const load = async () => {
      setLoadingRelays(true);
      try {
        const [fleetData, configData] = await Promise.all([
          fetchRelays(),
          fetchRelayConfig()
        ]);
        if (!active) return;
        const items = Array.isArray(fleetData?.items) ? fleetData.items : [];
        setRelays(items);
        setRelayConfig({
          enrollmentEnabled: !!configData?.enrollmentEnabled,
          certificateRequired: configData?.certificateRequired !== false,
          certificateTtlSeconds: Number(configData?.certificateTtlSeconds) || 2592000,
          enrollmentTokenTtlSeconds: Number(configData?.enrollmentTokenTtlSeconds) || 600,
          tokenTtlSeconds: Number(configData?.tokenTtlSeconds) || 86400,
          heartbeatStaleSeconds: Number(configData?.heartbeatStaleSeconds) || 90
        });
        setRelayError('');
      } catch (error) {
        if (!active) return;
        setRelayError(error.message || 'Unable to load relay fabric');
      } finally {
        if (active) setLoadingRelays(false);
      }
    };
    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(interval);
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
      setLiveSecurityAlerts([]);
      setLiveSecurityIncident(null);
      setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
      setActiveSecurityIncident({ active: false, incident: null });
      securityFeedBootstrappedRef.current = false;
      lastSecurityAuditIdRef.current = 0;
      liveAlertCooldownByTypeRef.current = {};
      liveIncidentCriticalTimestampsRef.current = [];
      liveIncidentCooldownUntilRef.current = 0;
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

  useEffect(() => {
    if (!auth.token || !canViewAudit) {
      setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
      return;
    }
    let active = true;
    const load = () => {
      fetchContainmentStatus()
        .then((data) => {
          if (!active) return;
          setContainmentStatus({
            enabled: !!data?.enabled,
            updatedAt: data?.updatedAt || '',
            updatedBy: data?.updatedBy || '',
            reason: data?.reason || ''
          });
        })
        .catch(() => {
          if (!active) return;
          setContainmentStatus({ enabled: false, updatedAt: '', updatedBy: '', reason: '' });
        });
    };
    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit]);

  useEffect(() => {
    if (!auth.token || !canViewAudit) {
      setActiveSecurityIncident({ active: false, incident: null });
      return;
    }
    let active = true;
    const load = () => {
      fetchActiveSecurityIncident()
        .then((data) => {
          if (!active) return;
          setActiveSecurityIncident({
            active: !!data?.active,
            incident: data?.incident || null
          });
        })
        .catch(() => {
          if (!active) return;
          setActiveSecurityIncident({ active: false, incident: null });
        });
    };
    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit]);

  useEffect(() => {
    if (!auth.token || !canViewAudit) {
      return undefined;
    }

    let active = true;
    const load = async () => {
      try {
        const sinceId = lastSecurityAuditIdRef.current;
        const data = await fetchSecurityAlerts(sinceId);
        if (!active) return;

        const nextMaxId = Number(data?.maxEventId) || sinceId;
        const items = Array.isArray(data?.items) ? data.items : [];

        if (!securityFeedBootstrappedRef.current) {
          securityFeedBootstrappedRef.current = true;
          lastSecurityAuditIdRef.current = Math.max(sinceId, nextMaxId);
          return;
        }

        if (items.length) {
          const nowMs = Date.now();
          const incidentWindowMs = 5 * 60 * 1000;
          const incidentThreshold = 3;
          const nextCriticalTimestamps = [
            ...liveIncidentCriticalTimestampsRef.current.filter((ts) => ts >= nowMs - incidentWindowMs),
            ...items
              .filter((item) => String(item.severity || '').toLowerCase() === 'critical')
              .map((item) => Date.parse(item.createdAt || '') || nowMs)
          ];
          liveIncidentCriticalTimestampsRef.current = nextCriticalTimestamps;

          if (
            nextCriticalTimestamps.length >= incidentThreshold &&
            nowMs >= liveIncidentCooldownUntilRef.current
          ) {
            liveIncidentCooldownUntilRef.current = nowMs + incidentWindowMs;
            setLiveSecurityIncident({
              key: `incident:${nowMs}`,
              createdAt: new Date(nowMs).toISOString(),
              criticalCount: nextCriticalTimestamps.length,
              title: 'Potential Security Incident',
              hint: 'Multiple critical signals observed in a short window. Escalate and investigate immediately.'
            });
            reportSecurityIncidentEscalation({
              criticalCount: nextCriticalTimestamps.length,
              windowSeconds: Math.floor(incidentWindowMs / 1000),
              profile: liveAlertProfile
            }).catch(() => {
              // Keep incident UX independent from audit reporting failures.
            });

            if (!activeSecurityIncident?.active) {
              openSecurityIncident({
                criticalCount: nextCriticalTimestamps.length,
                windowSeconds: Math.floor(incidentWindowMs / 1000),
                profile: liveAlertProfile,
                title: 'Potential Security Incident',
                summary: 'Automatically opened from repeated critical live security signals.'
              })
                .then((opened) => {
                  setActiveSecurityIncident({
                    active: !!opened?.active,
                    incident: opened?.incident || null
                  });
                })
                .catch(() => {
                  // Keep signal-to-incident UI non-blocking.
                });
            }
          }

          setLiveSecurityAlerts((prev) => {
            const existing = new Set(prev.map((item) => item.key));
            const throttledBySeverity = { critical: 0, warning: 0, ok: 0 };
            const incoming = items
              .map((item) => ({
                key: `${item.id}:${item.eventType}`,
                eventType: item.eventType,
                sessionId: Number(item.sessionId) || null,
                createdAt: item.createdAt,
                severity: item.severity || 'warning',
                title: item.title || 'Security Signal',
                hint: item.hint || 'Investigate in audit timeline.'
              }))
              .sort(compareLiveAlertPriority)
              .filter((item) => {
                if (existing.has(item.key)) return false;
                const baseCooldown = LIVE_ALERT_COOLDOWN_MS[item.severity] ?? 60000;
                const cooldownMs = Math.round(
                  baseCooldown * (activeLiveAlertProfile.cooldownMultiplier || 1)
                );
                const cooldownKey = item.eventType || item.severity;
                const lastShownAt = liveAlertCooldownByTypeRef.current[cooldownKey] || 0;
                if (nowMs - lastShownAt < cooldownMs) {
                  throttledBySeverity[item.severity] =
                    (throttledBySeverity[item.severity] || 0) + 1;
                  return false;
                }
                liveAlertCooldownByTypeRef.current[cooldownKey] = nowMs;
                return true;
              });

            const suppressedCount = Object.values(throttledBySeverity).reduce(
              (sum, count) => sum + count,
              0
            );
            if (suppressedCount > 0) {
              incoming.push({
                key: `throttled:${nowMs}`,
                eventType: 'security.alerts.throttled',
                createdAt: new Date(nowMs).toISOString(),
                severity:
                  throttledBySeverity.warning > 0 || throttledBySeverity.critical > 0
                    ? 'warning'
                    : 'ok',
                title: `${suppressedCount} signal${suppressedCount > 1 ? 's' : ''} grouped`,
                hint: 'Low-priority duplicates were throttled to keep focus on high-risk events.'
              });
            }

            const merged = [...incoming, ...prev].sort(compareLiveAlertPriority);
            return capLiveAlertsBySeverity(merged, activeLiveAlertProfile.maxVisible);
          });
        }

        lastSecurityAuditIdRef.current = Math.max(sinceId, nextMaxId);
      } catch (_) {
        // Keep security feed non-blocking for the rest of the UI.
      }
    };

    load();
    const interval = window.setInterval(load, 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [auth.token, canViewAudit, activeLiveAlertProfile, activeSecurityIncident]);

  useEffect(() => {
    if (!liveSecurityAlerts.length) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      setLiveSecurityAlerts((prev) => prev.slice(0, -1));
    }, 9000);
    return () => window.clearTimeout(timer);
  }, [liveSecurityAlerts]);

  const dismissLiveSecurityAlert = (alertKey) => {
    setLiveSecurityAlerts((prev) => prev.filter((item) => item.key !== alertKey));
  };

  const dismissLiveSecurityIncident = () => {
    setLiveSecurityIncident(null);
  };

  const incidentSuspectSessions = useMemo(() => {
    if (!liveSecurityIncident) return [];
    const incidentTs = Date.parse(liveSecurityIncident.createdAt || '') || Date.now();
    const since = incidentTs - 5 * 60 * 1000;
    const bySessionId = new Map();

    const touchSuspicion = (sessionId, severity, createdAt) => {
      if (!sessionId || sessionId <= 0) return;
      const existing = bySessionId.get(sessionId) || {
        sessionId,
        signals: 0,
        criticalSignals: 0,
        lastSignalAt: 0
      };
      const signalTs = Date.parse(createdAt || '') || incidentTs;
      existing.signals += 1;
      if (String(severity || '').toLowerCase() === 'critical') {
        existing.criticalSignals += 1;
      }
      existing.lastSignalAt = Math.max(existing.lastSignalAt, signalTs);
      bySessionId.set(sessionId, existing);
    };

    securityAuditItems.forEach((item) => {
      const created = Date.parse(item?.createdAt || '') || 0;
      if (created < since) return;
      const type = String(item?.type || '').toLowerCase();
      const isSuspicious =
        type.includes('behavior.anomaly') ||
        type.includes('session.create.unjustified') ||
        (type.includes('session.dna') && type.includes('mismatch'));
      if (!isSuspicious) return;
      const sid = extractSessionIdFromAuditItem(item);
      const severity = type.includes('mismatch') ? 'critical' : 'warning';
      touchSuspicion(sid, severity, item?.createdAt);
    });

    liveSecurityAlerts.forEach((item) => {
      const created = Date.parse(item?.createdAt || '') || 0;
      if (created < since) return;
      const sid = Number(item?.sessionId) || 0;
      touchSuspicion(sid, item?.severity, item?.createdAt);
    });

    return Array.from(bySessionId.values())
      .map((entry) => {
        const matched = sessions.find((session) => session.id === entry.sessionId) || {
          id: entry.sessionId,
          status: 'unknown',
          target: 'n/a',
          user: 'n/a'
        };
        const minutesSince = Math.max(0, Math.floor((incidentTs - entry.lastSignalAt) / 60000));
        const recencyBonus = Math.max(0, 20 - minutesSince * 4);
        const activeBonus = matched.status === 'active' ? 30 : 0;
        const score =
          entry.signals * 20 +
          entry.criticalSignals * 25 +
          activeBonus +
          recencyBonus;
        return {
          ...matched,
          score,
          signals: entry.signals,
          criticalSignals: entry.criticalSignals,
          lastSignalAt: entry.lastSignalAt
        };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, 4);
  }, [liveSecurityIncident, securityAuditItems, liveSecurityAlerts, sessions]);

  const activeIncidentSuspectSessions = useMemo(
    () => incidentSuspectSessions.filter((session) => session.status === 'active'),
    [incidentSuspectSessions]
  );

  const requestTerminateIncidentSuspects = () => {
    if (!canOperateSessions) {
      setSessionError('You are not allowed to terminate sessions.');
      return;
    }
    if (!activeIncidentSuspectSessions.length) {
      setSessionError('No active correlated suspect sessions to terminate.');
      return;
    }
    setIncidentTerminateConfirmOpen(true);
  };

  const confirmTerminateIncidentSuspects = async () => {
    if (!activeIncidentSuspectSessions.length || incidentTerminateBusy) {
      return;
    }
    setIncidentTerminateBusy(true);
    try {
      const ids = activeIncidentSuspectSessions.map((session) => session.id);
      const results = await Promise.allSettled(ids.map((id) => terminateSession(id)));
      const updatedById = new Map();
      let failed = 0;
      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          updatedById.set(ids[index], result.value);
        } else {
          failed += 1;
        }
      });

      if (updatedById.size > 0) {
        setSessions((prev) =>
          prev.map((item) => updatedById.get(item.id) || item)
        );
      }

      if (failed > 0) {
        setSessionError(`${failed} suspect session(s) could not be terminated.`);
      } else {
        setSessionError('');
      }
    } catch (error) {
      setSessionError(error.message || 'Unable to terminate correlated suspect sessions');
    } finally {
      setIncidentTerminateBusy(false);
      setIncidentTerminateConfirmOpen(false);
    }
  };

  const setContainmentEnabled = async (enabled) => {
    if (containmentBusy) return;
    if (!canManagePlatform) {
      setSessionError('Only platform admins can change containment mode.');
      return;
    }
    setContainmentBusy(true);
    try {
      const payload = await setContainmentMode({
        enabled,
        reason: liveSecurityIncident?.title || 'incident.escalation'
      });
      setContainmentStatus({
        enabled: !!payload?.enabled,
        updatedAt: payload?.updatedAt || '',
        updatedBy: payload?.updatedBy || auth.user,
        reason: payload?.reason || ''
      });
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to update containment mode');
    } finally {
      setContainmentBusy(false);
    }
  };

  const openIncidentCase = async () => {
    if (incidentCaseBusy) return;
    setIncidentCaseBusy(true);
    try {
      const payload = await openSecurityIncident({
        criticalCount: Number(liveSecurityIncident?.criticalCount || 0),
        windowSeconds: 300,
        profile: liveAlertProfile,
        title: liveSecurityIncident?.title || 'Potential Security Incident',
        summary: liveSecurityIncident?.hint || 'Opened manually from incident banner.'
      });
      setActiveSecurityIncident({
        active: !!payload?.active,
        incident: payload?.incident || null
      });
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to open incident case');
    } finally {
      setIncidentCaseBusy(false);
    }
  };

  const closeIncidentCase = async () => {
    if (incidentCaseBusy || !activeSecurityIncident?.active) return;
    setIncidentCaseBusy(true);
    try {
      await closeSecurityIncident({
        reason: liveSecurityIncident?.title || 'Incident mitigated and closed from UI'
      });
      setActiveSecurityIncident((prev) => ({
        active: false,
        incident: prev?.incident
          ? {
              ...prev.incident,
              closedAt: new Date().toISOString(),
              closeReason: liveSecurityIncident?.title || 'Incident mitigated and closed from UI'
            }
          : prev?.incident
      }));
      setSessionError('');
    } catch (error) {
      setSessionError(error.message || 'Unable to close incident case');
    } finally {
      setIncidentCaseBusy(false);
    }
  };

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
    const { name, value, type, checked } = event.target;
    setUserForm((prev) => ({ ...prev, [name]: type === 'checkbox' ? checked : value }));
  };

  const onAccessPolicyFieldChange = (event) => {
    const { name, value, type, checked } = event.target;
    setAccessPolicyForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const onAccessProfileFieldChange = (event) => {
    const { name, value } = event.target;
    setAccessProfileForm((prev) => ({ ...prev, [name]: value }));
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
      if (payload.status === 'mfa_required' || payload.status === '2fa_required') {
        setTwoFARequired(true);
        setTotpCode('');
        setAvailableMfaMethods(Array.isArray(payload.mfaMethods) ? payload.mfaMethods : (payload.totpEnabled ? ['totp'] : []));
        setWebauthnLoginOptions(payload.webauthn || null);
        setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
        setAuthError('');
        return;
      }

      setTwoFARequired(false);
      setAvailableMfaMethods([]);
      setWebauthnLoginOptions(null);
      setTotpCode('');
      const bootstrap = payload.bootstrap || {};
      setAuth((prev) => ({
        ...prev,
        token: payload.token,
        role: normalizeRole(payload.role),
        user: payload.user,
        permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setWebauthnEnabled(!!payload.webauthnEnabled);
      setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!payload.totpEnabled,
        webauthnEnabled: !!payload.webauthnEnabled
      });
      setChangePwCurrent(bootstrap.passwordChangeRequired ? auth.password : '');
      setTotpSetupData(null);
      setTotpQrDataUrl('');
      setTotpSetupCode('');
      setTotpError('');
      setTotpCopyStatus('');
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: normalizeRole(payload.role),
        permissions: Array.isArray(payload.permissions) ? payload.permissions : []
      }));
      setAuthError('');
      navigate('/');
    } catch (error) {
      setAuthError(error.message || t('auth.loginFailed'));
    }
  };

  const onStartSsoLogin = () => {
    setAuthError('');
    startOidcSso({ postLoginRedirect: '/' });
  };

  const onLoginWithPasskey = async () => {
    if (!webauthnLoginOptions) {
      setAuthError(t('auth.noPasskeyChallenge'));
      return;
    }
    setWebauthnBusy(true);
    setAuthError('');
    try {
      const assertion = await getBrowserPasskeyAssertion(webauthnLoginOptions);
      const payload = await login({
        user: auth.user,
        password: auth.password,
        webauthnRequestId: webauthnLoginOptions.requestId,
        webauthnCredentialId: assertion.credentialId,
        webauthnAuthenticatorData: assertion.authenticatorData,
        webauthnClientDataJSON: assertion.clientDataJSON,
        webauthnSignature: assertion.signature
      });
      if (payload.status === 'mfa_required') {
        setWebauthnLoginOptions(payload.webauthn || null);
        throw new Error(payload.message || t('auth.passkeyStillRequired'));
      }
      const bootstrap = payload.bootstrap || {};
      setTwoFARequired(false);
      setAvailableMfaMethods([]);
      setWebauthnLoginOptions(null);
      setTotpCode('');
      setAuth((prev) => ({
        ...prev,
        token: payload.token,
        role: normalizeRole(payload.role),
        user: payload.user,
        permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
        password: ''
      }));
      setAuthToken(payload.token);
      setTotpEnabled(!!payload.totpEnabled);
      setWebauthnEnabled(!!payload.webauthnEnabled);
      setPreferredMfaMethod(String(payload.preferredMfaMethod || 'any'));
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!payload.totpEnabled,
        webauthnEnabled: !!payload.webauthnEnabled
      });
      setTokenExpiresAt(payload.expiresAt || '');
      localStorage.setItem('endoriumfort_auth', JSON.stringify({
        token: payload.token,
        user: payload.user,
        role: normalizeRole(payload.role),
        permissions: Array.isArray(payload.permissions) ? payload.permissions : []
      }));
      navigate('/');
    } catch (error) {
      setAuthError(error.message || t('auth.passkeySignInFailed'));
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onLogout = async () => {
    try { await logout(); } catch (_) {}
    setAuth((prev) => ({ ...prev, token: '', password: '', permissions: [] }));
    setAuthToken('');
    setTokenExpiresAt('');
    setBootstrapState({
      required: false,
      passwordChangeRequired: false,
      mfaSetupRequired: false,
      totpEnabled: false,
      webauthnEnabled: false
    });
    setWebauthnEnabled(false);
    setWebauthnCredentials([]);
    setWebauthnLoginOptions(null);
    setAvailableMfaMethods([]);
    setPreferredMfaMethod('any');
    setTotpSetupData(null);
    setTotpQrDataUrl('');
    setTotpCopyStatus('');
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
        requests.push(fetchRelays());
        requests.push(fetchRelayConfig());
      }
      if (canViewAudit) {
        requests.push(fetchAudit());
        requests.push(fetchContainmentStatus());
        requests.push(fetchActiveSecurityIncident());
      }
      const results = await Promise.all(requests);
      const [
        sessionData,
        resourceData,
        statsData,
        maybeUsers,
        maybeRelays,
        maybeRelayConfig,
        maybeAudit,
        maybeContainment,
        maybeIncident
      ] = results;

      setSessions(Array.isArray(sessionData?.items) ? sessionData.items : []);
      setResources(Array.isArray(resourceData?.items) ? resourceData.items : []);
      setStats(statsData || null);
      if (canManagePlatform) {
        setUsers(Array.isArray(maybeUsers?.items) ? maybeUsers.items : []);
        setRelays(Array.isArray(maybeRelays?.items) ? maybeRelays.items : []);
        setRelayConfig({
          enrollmentEnabled: !!maybeRelayConfig?.enrollmentEnabled,
          certificateRequired: maybeRelayConfig?.certificateRequired !== false,
          certificateTtlSeconds: Number(maybeRelayConfig?.certificateTtlSeconds) || 2592000,
          enrollmentTokenTtlSeconds: Number(maybeRelayConfig?.enrollmentTokenTtlSeconds) || 600,
          tokenTtlSeconds: Number(maybeRelayConfig?.tokenTtlSeconds) || 86400,
          heartbeatStaleSeconds: Number(maybeRelayConfig?.heartbeatStaleSeconds) || 90
        });
      }
      if (canViewAudit) {
        const auditData = canManagePlatform ? maybeAudit : maybeUsers;
        const items = Array.isArray(auditData?.items) ? auditData.items : [];
        setSecurityAuditItems(items);
        const containmentData = canManagePlatform ? maybeContainment : maybeAudit;
        setContainmentStatus({
          enabled: !!containmentData?.enabled,
          updatedAt: containmentData?.updatedAt || '',
          updatedBy: containmentData?.updatedBy || '',
          reason: containmentData?.reason || ''
        });
        const incidentData = canManagePlatform ? maybeIncident : maybeContainment;
        setActiveSecurityIncident({
          active: !!incidentData?.active,
          incident: incidentData?.incident || null
        });
        if (auditOpen) {
          setAuditItems(items);
        }
      }
      try {
        const grantsData = await fetchAccessGrants();
        setAccessGrants(Array.isArray(grantsData?.items) ? grantsData.items : []);
      } catch (_) {}
      if (canManagePlatform) {
        try {
          const [policyData, profileData] = await Promise.all([
            fetchAccessPolicies(),
            fetchAccessProfiles()
          ]);
          setAccessPolicies(Array.isArray(policyData?.items) ? policyData.items : []);
          setAccessProfiles(Array.isArray(profileData?.items) ? profileData.items : []);
        } catch (_) {}
      }
      setSessionError('');
      setResourceError('');
      setUserError('');
      setSecurityAuditError('');
    } catch (error) {
      setSessionError(error.message || t('feedback.unableRefreshData'));
    } finally {
      setQuickRefreshing(false);
    }
  };

  const loadEnterpriseFoundations = async () => {
    setEnterpriseLoading(true);
    setEnterpriseError('');
    setEnterpriseClusterPeerMessage('');
    try {
      const [
        directoryData,
        ldapConfigData,
        providersData,
        configData,
        scimConfigData,
        itsmData,
        siemData,
        clusterStatusData,
        clusterConfigData
      ] = await Promise.all([
        fetchDirectoryProviders(),
        fetchLdapConfig(),
        fetchSsoProviders(),
        fetchSsoConfig(),
        fetchScimServiceProviderConfig(),
        fetchItsmProviders(),
        fetchSiemChannels(),
        fetchClusterStatus(),
        fetchClusterConfig()
      ]);

      const nextDirectoryProviders = Array.isArray(directoryData?.items) ? directoryData.items : [];
      const nextSsoProviders = Array.isArray(providersData?.items) ? providersData.items : [];
      const nextItsmProviders = Array.isArray(itsmData?.items) ? itsmData.items : [];
      const nextSiemChannels = Array.isArray(siemData?.items) ? siemData.items : [];

      setEnterpriseDirectoryProviders(nextDirectoryProviders);
      setEnterpriseLdapConfig(ldapConfigData?.config || null);
      setEnterpriseSsoProviders(nextSsoProviders);
      setEnterpriseSsoConfig(configData || null);
      setEnterpriseScimConfig(scimConfigData || null);
      setEnterpriseItsmProviders(nextItsmProviders);
      setEnterpriseSiemChannels(nextSiemChannels);
      setEnterpriseClusterStatus(clusterStatusData || null);
      setEnterpriseClusterConfig(clusterConfigData || null);

      const defaultSsoProvider = String(configData?.defaultProvider || nextSsoProviders[0]?.id || '');
      setEnterpriseSsoProvider((prev) =>
        prev && nextSsoProviders.some((item) => String(item.id) === prev)
          ? prev
          : defaultSsoProvider
      );

      const defaultItsmProvider = String(nextItsmProviders[0]?.id || 'servicenow');
      setEnterpriseItsmProvider((prev) =>
        nextItsmProviders.some((item) => String(item.id) === prev)
          ? prev
          : defaultItsmProvider
      );

      const defaultSiemChannel = String(nextSiemChannels[0]?.id || 'json_webhook');
      setEnterpriseSiemChannel((prev) =>
        nextSiemChannels.some((item) => String(item.id) === prev)
          ? prev
          : defaultSiemChannel
      );

      const deliveryMode = String(siemData?.defaultDeliveryMode || '').toLowerCase();
      if (deliveryMode === 'fail-open' || deliveryMode === 'fail-closed') {
        setEnterpriseSiemDeliveryMode(deliveryMode);
      }
      setEnterpriseError('');
    } catch (error) {
      setEnterpriseError(error.message || (locale === 'fr'
        ? 'Impossible de charger les fondations Enterprise IAM.'
        : 'Unable to load enterprise IAM foundations.'));
    } finally {
      setEnterpriseLoading(false);
    }
  };

  const loadEnterpriseScimDirectory = async (override = {}) => {
    const startIndex = clampInteger(override.startIndex ?? enterpriseScimStartIndex, 1, 1, 1000000);
    const count = clampInteger(override.count ?? enterpriseScimCount, 20, 0, 200);
    const filter = String(override.filter ?? enterpriseScimFilter).trim();
    const params = { startIndex, count };
    if (filter) {
      params.filter = filter;
    }

    setEnterpriseScimLoading(true);
    setEnterpriseScimError('');
    try {
      const [usersData, groupsData] = await Promise.all([
        fetchScimUsers(params),
        fetchScimGroups(params)
      ]);
      setEnterpriseScimUsers(Array.isArray(usersData?.Resources) ? usersData.Resources : []);
      setEnterpriseScimGroups(Array.isArray(groupsData?.Resources) ? groupsData.Resources : []);
      setEnterpriseScimMeta({
        users: {
          totalResults: Number(usersData?.totalResults) || 0,
          startIndex: Number(usersData?.startIndex) || startIndex,
          itemsPerPage: Number(usersData?.itemsPerPage) || 0
        },
        groups: {
          totalResults: Number(groupsData?.totalResults) || 0,
          startIndex: Number(groupsData?.startIndex) || startIndex,
          itemsPerPage: Number(groupsData?.itemsPerPage) || 0
        }
      });
      setEnterpriseScimStartIndex(String(startIndex));
      setEnterpriseScimCount(String(count));
    } catch (error) {
      setEnterpriseScimError(error.message || (locale === 'fr'
        ? 'Impossible d’interroger le répertoire SCIM.'
        : 'Unable to query SCIM directory.'));
    } finally {
      setEnterpriseScimLoading(false);
    }
  };

  const refreshEnterpriseWorkspace = async () => {
    await loadEnterpriseFoundations();
    await loadEnterpriseScimDirectory();
  };

  const onStartEnterpriseSso = () => {
    const selectedProvider = String(enterpriseSsoProvider || enterpriseSsoConfig?.defaultProvider || '');
    startOidcSso({
      provider: selectedProvider || undefined,
      postLoginRedirect: '/'
    });
  };

  const onSubmitEnterpriseLdapTest = async (event) => {
    event.preventDefault();
    const username = String(enterpriseLdapTestUsername || '').trim();
    const password = String(enterpriseLdapTestPassword || '');
    if (!username || !password) {
      setEnterpriseLdapTestResult({
        error: true,
        message: locale === 'fr'
          ? 'Renseignez un utilisateur et un mot de passe LDAP.'
          : 'Provide LDAP username and password.'
      });
      return;
    }

    setEnterpriseLdapTesting(true);
    try {
      const payload = await testLdapBind({ username, password });
      setEnterpriseLdapTestResult(payload || null);
    } catch (error) {
      setEnterpriseLdapTestResult({
        error: true,
        message: error.message || (locale === 'fr'
          ? 'Le test de bind LDAP a échoué.'
          : 'LDAP bind test failed.')
      });
    } finally {
      setEnterpriseLdapTesting(false);
    }
  };

  const onSubmitEnterpriseScimFilter = async (event) => {
    event.preventDefault();
    await loadEnterpriseScimDirectory();
  };

  const onSubmitEnterpriseScimPatch = async (event) => {
    event.preventDefault();
    const target = String(enterpriseScimPatchId || '').trim();
    if (!target) {
      setEnterpriseScimPatchResult(locale === 'fr'
        ? 'Renseignez un identifiant SCIM (ID ou userName).'
        : 'Provide a SCIM target (id or userName).');
      return;
    }

    const operations = [];
    const nextUserName = String(enterpriseScimPatchUsername || '').trim();
    const nextRole = String(enterpriseScimPatchRole || '').trim();
    if (nextUserName) {
      operations.push({ op: 'replace', path: 'userName', value: nextUserName });
    }
    if (nextRole) {
      operations.push({ op: 'replace', path: 'role', value: nextRole });
    }
    if (enterpriseScimPatchActive === 'active') {
      operations.push({ op: 'replace', path: 'active', value: true });
    }
    if (enterpriseScimPatchActive === 'inactive') {
      operations.push({ op: 'replace', path: 'active', value: false });
    }

    if (!operations.length) {
      setEnterpriseScimPatchResult(locale === 'fr'
        ? 'Aucune opération PATCH à appliquer.'
        : 'No PATCH operation to apply.');
      return;
    }

    setEnterpriseScimPatchLoading(true);
    try {
      const response = await patchScimUser(target, operations);
      if (response && response.userName) {
        setEnterpriseScimPatchResult(locale === 'fr'
          ? `Utilisateur SCIM mis à jour: ${response.userName}`
          : `SCIM user updated: ${response.userName}`);
      } else {
        setEnterpriseScimPatchResult(locale === 'fr'
          ? 'Patch SCIM appliqué avec succès.'
          : 'SCIM patch applied successfully.');
      }
      await loadEnterpriseScimDirectory();
    } catch (error) {
      setEnterpriseScimPatchResult(error.message || (locale === 'fr'
        ? 'Le patch SCIM a échoué.'
        : 'SCIM patch failed.'));
    } finally {
      setEnterpriseScimPatchLoading(false);
    }
  };

  const onSubmitEnterpriseItsmVerification = async (event) => {
    event.preventDefault();
    const ticketId = String(enterpriseItsmTicketId || '').trim();
    if (!ticketId) {
      setEnterpriseItsmResult({
        error: true,
        message: locale === 'fr' ? 'Renseignez un ticket ITSM.' : 'Provide an ITSM ticket id.'
      });
      return;
    }
    setEnterpriseItsmLoading(true);
    try {
      const payload = await verifyItsmTicket({
        provider: enterpriseItsmProvider,
        ticketId,
        failMode: enterpriseItsmFailMode,
        simulateUnavailable: !!enterpriseItsmUnavailable
      });
      setEnterpriseItsmResult(payload || null);
    } catch (error) {
      setEnterpriseItsmResult({
        error: true,
        message: error.message || (locale === 'fr' ? 'Vérification ITSM impossible.' : 'Unable to verify ITSM ticket.')
      });
    } finally {
      setEnterpriseItsmLoading(false);
    }
  };

  const onSubmitEnterpriseSiemDispatch = async (event) => {
    event.preventDefault();
    const eventType = String(enterpriseSiemEventType || '').trim();
    if (!eventType) {
      setEnterpriseSiemResult({
        error: true,
        message: locale === 'fr' ? 'Renseignez un type d’événement SIEM.' : 'Provide a SIEM event type.'
      });
      return;
    }
    setEnterpriseSiemLoading(true);
    try {
      const payload = await forwardSiemEvent({
        channel: enterpriseSiemChannel,
        eventType,
        deliveryMode: enterpriseSiemDeliveryMode,
        simulateFailure: !!enterpriseSiemSimulateFailure
      });
      setEnterpriseSiemResult(payload || null);
    } catch (error) {
      setEnterpriseSiemResult({
        error: true,
        message: error.message || (locale === 'fr' ? 'Forward SIEM impossible.' : 'Unable to forward SIEM event.')
      });
    } finally {
      setEnterpriseSiemLoading(false);
    }
  };

  const onRemoveEnterpriseClusterPeer = async (nodeId) => {
    const normalized = String(nodeId || '').trim();
    if (!normalized) return;
    setEnterpriseClusterPeerBusy(normalized);
    setEnterpriseClusterPeerMessage('');
    try {
      await removeClusterPeer(normalized);
      setEnterpriseClusterPeerMessage(locale === 'fr'
        ? `Noeud retire: ${normalized}`
        : `Peer removed: ${normalized}`);
      await loadEnterpriseFoundations();
    } catch (error) {
      setEnterpriseClusterPeerMessage(error.message || (locale === 'fr'
        ? 'Suppression du noeud impossible.'
        : 'Unable to remove cluster peer.'));
    } finally {
      setEnterpriseClusterPeerBusy('');
    }
  };

  useEffect(() => {
    if (!auth.token || !canManagePlatform) {
      setEnterpriseLoading(false);
      setEnterpriseError('');
      setEnterpriseDirectoryProviders([]);
      setEnterpriseLdapConfig(null);
      setEnterpriseLdapTestUsername('');
      setEnterpriseLdapTestPassword('');
      setEnterpriseLdapTestResult(null);
      setEnterpriseSsoProviders([]);
      setEnterpriseSsoProvider('');
      setEnterpriseSsoConfig(null);
      setEnterpriseScimConfig(null);
      setEnterpriseScimUsers([]);
      setEnterpriseScimGroups([]);
      setEnterpriseScimMeta({
        users: { totalResults: 0, startIndex: 1, itemsPerPage: 0 },
        groups: { totalResults: 0, startIndex: 1, itemsPerPage: 0 }
      });
      setEnterpriseScimError('');
      setEnterpriseScimPatchResult('');
      setEnterpriseItsmProviders([]);
      setEnterpriseItsmResult(null);
      setEnterpriseSiemChannels([]);
      setEnterpriseSiemResult(null);
      setEnterpriseClusterStatus(null);
      setEnterpriseClusterConfig(null);
      setEnterpriseClusterPeerBusy('');
      setEnterpriseClusterPeerMessage('');
      return;
    }
    if (adminSection !== 'enterprise') {
      return;
    }
    refreshEnterpriseWorkspace().catch(() => {});
  }, [adminSection, auth.token, canManagePlatform]);

  const onTerminate = async (sessionId) => {
    try {
      const updated = await terminateSession(sessionId);
      setSessions((prev) =>
        prev.map((item) => (item.id === sessionId ? updated : item))
      );
    } catch (error) {
      setSessionError(error.message || t('feedback.unableTerminateSession'));
    }
  };

  const toggleWatchSession = (sessionId) => {
    const normalized = Number(sessionId) || 0;
    if (!normalized) return;
    setWatchedSessionIds((prev) =>
      prev.includes(normalized)
        ? prev.filter((id) => id !== normalized)
        : [...prev, normalized]
    );
  };

  const dismissWatchAlert = (alertKey) => {
    setWatchlistAlerts((prev) => prev.filter((item) => item.key !== alertKey));
  };

  const loadAudit = async () => {
    if (!auth.token) {
      setAuditError(t('app.auditorRoleHint'));
      return;
    }
    setLoadingAudit(true);
    try {
      const data = await fetchAudit();
      setAuditItems(Array.isArray(data.items) ? data.items : []);
      setAuditError('');
    } catch (error) {
      setAuditError(error.message || t('feedback.unableLoadAudit'));
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
      if (terminalInputListenerRef.current) {
        terminalInputListenerRef.current.dispose();
        terminalInputListenerRef.current = null;
      }
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

  const resolveSessionResource = (session) => {
    if (!session) return null;
    const sessionResourceId = Number(session.resourceId) || 0;
    if (sessionResourceId > 0) {
      const byId = resources.find((item) => Number(item.id) === sessionResourceId);
      if (byId) return byId;
    }

    const sessionTarget = String(session.target || '').trim();
    const sessionProtocol = String(session.protocol || '').toLowerCase();
    const sessionPort = Number(session.port) || 0;

    return resources.find((item) => {
      const resourceTarget = String(item.target || '').trim();
      const resourceProtocol = String(item.protocol || '').toLowerCase();
      const resourcePort = Number(item.port) || 0;
      if (!resourceTarget || !resourceProtocol || resourcePort <= 0) {
        return false;
      }
      return (
        resourceTarget === sessionTarget &&
        resourceProtocol === sessionProtocol &&
        resourcePort === sessionPort
      );
    }) || null;
  };

  useEffect(() => {
    if (!auth.token || !sessions.length) {
      setSessionRelayHints({});
      return;
    }

    const resourceIds = Array.from(
      new Set(
        sessions
          .map((session) => Number(resolveSessionResource(session)?.id) || 0)
          .filter((id) => id > 0)
      )
    );

    if (!resourceIds.length) {
      setSessionRelayHints({});
      return;
    }

    let active = true;
    Promise.all(
      resourceIds.map(async (resourceId) => {
        try {
          const data = await fetchRelayResolution(resourceId);
          return [resourceId, data];
        } catch (_) {
          return [resourceId, null];
        }
      })
    )
      .then((entries) => {
        if (!active) return;
        const resolutionByResourceId = {};
        entries.forEach(([resourceId, data]) => {
          resolutionByResourceId[resourceId] = data;
        });

        const hints = {};
        sessions.forEach((session) => {
          const resourceId = Number(resolveSessionResource(session)?.id) || 0;
          if (!resourceId) return;
          const resolution = resolutionByResourceId[resourceId];
          const route = String(resolution?.route || 'direct').toLowerCase() === 'relay' ? 'relay' : 'direct';
          const relayLabel = resolution?.relay?.label || resolution?.relay?.relayId || '';
          const relayStatus = String(resolution?.relay?.status || '').toLowerCase() || 'offline';
          hints[session.id] = {
            route,
            relayLabel,
            relayStatus,
            relayAssigned: !!resolution?.relayAssigned
          };
        });
        setSessionRelayHints(hints);
      })
      .catch(() => {
        if (!active) return;
        setSessionRelayHints({});
      });

    return () => {
      active = false;
    };
  }, [auth.token, sessions, resources]);

  const openTerminal = async (session) => {
    setActiveTerminalSession(session);
    setSshPassword('');
    setTerminalError('');
    setTerminalInfo('');
    setTerminalStatus('idle');
    setTerminalReady(false);

    const resource = resolveSessionResource(session);
    if (!resource || !resource.hasCredentials) {
      setTerminalInfo(t('feedback.manualPasswordRequired'));
      return;
    }

    if ((resource.credentialSource || session.credentialSource || 'vaulted') !== 'vaulted') {
      setAutoConnectSessionId(session.id);
      setTerminalInfo('Brokered session ready. Credentials stay on the bastion.');
      return;
    }

    setTerminalInfo(t('feedback.autoReconnectAttempt'));

    try {
      const lease = await issueEphemeralCredential(resource.id);
      const creds = await consumeEphemeralCredential(lease.leaseId);
      if (creds.sshPassword) {
        setSshPassword(creds.sshPassword);
        setAutoConnectSessionId(session.id);
        setTerminalInfo(t('feedback.vaultCredentialsLoaded'));
      }
    } catch (_) {
      setTerminalInfo(t('feedback.automaticCredentialRecoveryFailed'));
    }
  };

  const buildWebSocketUrl = (path, params = {}) => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
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
    setTerminalInfo('');
    if (!activeTerminalSession) {
      setTerminalError(t('feedback.pickSessionToConnect'));
      return;
    }
    if (!sshPassword) {
      setTerminalError(t('feedback.sshPasswordRequired'));
      return;
    }
    if (!auth.token) {
      setTerminalError(t('feedback.signInFirst'));
      return;
    }

    const terminal = terminalInstanceRef.current;
    if (!terminal) {
      setTerminalError(t('feedback.terminalInitializing'));
      window.setTimeout(() => {
        if (terminalInstanceRef.current && auth.token && activeTerminalSession) {
          connectTerminal();
        }
      }, 150);
      return;
    }

    const wsUrl = buildWebSocketUrl('/api/ws/ssh');

    // Prevent duplicated key forwarding when reconnecting to the same terminal.
    if (terminalInputListenerRef.current) {
      terminalInputListenerRef.current.dispose();
      terminalInputListenerRef.current = null;
    }
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }

    const socket = new WebSocket(wsUrl);
    let socketOpened = false;
    socket.binaryType = 'arraybuffer';
    socketRef.current = socket;
    setTerminalStatus('connecting');

    socket.addEventListener('open', () => {
      if (socketRef.current !== socket) return;
      socketOpened = true;
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
      terminalInputListenerRef.current = terminal.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          // Some remote shells expect backspace as Ctrl-H (^H) instead of DEL.
          const normalizedInput = data.replace(/\x7f/g, '\b');
          socket.send(JSON.stringify({ type: 'input', data: normalizedInput }));
        }
      });
    });

    socket.addEventListener('message', (event) => {
      if (socketRef.current !== socket) return;
      if (typeof event.data === 'string') {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'error') {
            setTerminalError(payload.message || t('feedback.sshError'));
          }
        } catch (error) {
          terminal.write(event.data);
        }
        return;
      }
      const decoder = new TextDecoder();
      terminal.write(decoder.decode(event.data));
    });

    socket.addEventListener('close', (event) => {
      if (socketRef.current !== socket) return;
      if (terminalInputListenerRef.current) {
        terminalInputListenerRef.current.dispose();
        terminalInputListenerRef.current = null;
      }
      socketRef.current = null;
      if (!socketOpened) {
        setTerminalStatus('error');
        setTerminalError(t('feedback.sshRejected'));
        return;
      }
      if (event?.code === 1008 || event?.code === 1006) {
        setTerminalStatus('error');
        setTerminalError(t('feedback.sshInterrupted'));
        return;
      }
      setTerminalStatus('closed');
    });

    socket.addEventListener('error', () => {
      if (socketRef.current !== socket) return;
      setTerminalStatus('error');
      setTerminalError(t('feedback.websocketTransportError'));
    });
  };

  const sendSnippetToTerminal = (snippet, execute = false) => {
    if (!snippet?.command) return;
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setTerminalError(t('feedback.connectTerminalBeforeSnippets'));
      return;
    }
    const payload = execute ? `${snippet.command}\n` : snippet.command;
    socket.send(JSON.stringify({ type: 'input', data: payload }));
    setTerminalInfo(
      execute
        ? t('feedback.snippetExecuted', { label: snippet.label })
        : t('feedback.snippetInjected', { label: snippet.label })
    );
  };

  const addCustomSnippet = () => {
    const label = snippetLabel.trim();
    const command = snippetCommand.trim();
    if (!label || !command) {
      setTerminalError(t('feedback.snippetRequired'));
      return;
    }
    const id = `custom-${Date.now()}`;
    setCustomSnippets((prev) => [...prev, { id, label, command }]);
    setSnippetLabel('');
    setSnippetCommand('');
    setTerminalError('');
    setTerminalInfo(t('feedback.snippetSaved', { label }));
  };

  const removeCustomSnippet = (snippetId) => {
    setCustomSnippets((prev) => prev.filter((item) => item.id !== snippetId));
  };

  const clearAgentLaunchWatcher = () => {
    if (agentLaunchTimeoutRef.current) {
      window.clearTimeout(agentLaunchTimeoutRef.current);
      agentLaunchTimeoutRef.current = null;
    }
    if (typeof agentLaunchCleanupRef.current === 'function') {
      agentLaunchCleanupRef.current();
      agentLaunchCleanupRef.current = null;
    }
  };

  const isAgentTunnelProtocol = (protocol) => {
    const normalized = String(protocol || '').toLowerCase();
    return normalized === 'agent' || normalized === 'rdp';
  };

  const resolveAgentInstallGuide = () => {
    const ua = String(navigator.userAgent || '').toLowerCase();
    if (ua.includes('windows')) {
      return {
        platform: 'Windows',
        command: '.\\agent\\installers\\windows\\install-protocol.ps1 -AgentPath .\\agent\\endoriumfort-agent.exe'
      };
    }
    if (ua.includes('mac os') || ua.includes('macintosh') || ua.includes('darwin')) {
      return {
        platform: 'macOS',
        command: './agent/installers/macos/install-protocol.sh ./agent/endoriumfort-agent-darwin-arm64'
      };
    }
    return {
      platform: 'Linux',
      command: './agent/installers/linux/install-protocol.sh ./agent/endoriumfort-agent'
    };
  };

  const buildAgentLaunchPayload = (resource, localPort) => {
    const normalizedOrigin = String(window.location.origin || '').replace(/\/$/, '');
    const resourceProtocol = String(resource?.protocol || '').toLowerCase();
    const openInBrowser = resourceProtocol === 'agent' || resourceProtocol === 'http' || resourceProtocol === 'https';
    const localEndpoint = `127.0.0.1:${localPort}`;
    const localUrl = `http://127.0.0.1:${localPort}`;
    const params = new URLSearchParams();
    params.set('server', normalizedOrigin);
    params.set('resource', String(resource.id));
    params.set('local-port', String(localPort));
    if (openInBrowser) {
      params.set('redirect-url', localUrl);
    } else {
      params.set('no-browser', '1');
    }
    if (auth.token) {
      params.set('token', auth.token);
    }

    return {
      localUrl,
      localEndpoint,
      openInBrowser,
      installGuide: resolveAgentInstallGuide(),
      command: `endoriumfort-agent connect --server ${normalizedOrigin} --token ${auth.token} --resource ${resource.id} --local-port ${localPort}`,
      deepLink: `endoriumfort://connect?${params.toString()}`
    };
  };

  const launchAgentDeepLink = (deepLink) => {
    if (!deepLink) return;
    clearAgentLaunchWatcher();
    setAgentModal((prev) => (prev ? { ...prev, launchState: 'opening' } : prev));

    const onHidden = () => {
      if (document.visibilityState === 'hidden') {
        clearAgentLaunchWatcher();
        setAgentModal((prev) => (prev ? { ...prev, launchState: 'opened' } : prev));
      }
    };

    const onPageHide = () => {
      clearAgentLaunchWatcher();
      setAgentModal((prev) => (prev ? { ...prev, launchState: 'opened' } : prev));
    };

    document.addEventListener('visibilitychange', onHidden);
    window.addEventListener('pagehide', onPageHide, { once: true });
    agentLaunchCleanupRef.current = () => {
      document.removeEventListener('visibilitychange', onHidden);
      window.removeEventListener('pagehide', onPageHide);
    };

    agentLaunchTimeoutRef.current = window.setTimeout(() => {
      clearAgentLaunchWatcher();
      setAgentModal((prev) => (prev ? { ...prev, launchState: 'fallback' } : prev));
    }, 1600);

    window.location.href = deepLink;
  };

  useEffect(() => {
    return () => {
      clearAgentLaunchWatcher();
    };
  }, []);

  const connectToResource = async (resource, accessMeta = {}) => {
    if (!auth.token) {
      setSessionError(t('feedback.signInFirst'));
      return false;
    }

    const protocol = String(resource.protocol || '').toLowerCase();

    // Handle web resources via proxy
    if (protocol === 'http' || protocol === 'https') {
      setInlineWebResource(resource);
      setVncViewerSession(null);
      setMainTab('sessions');
      return true;
    }

    if (protocol === 'vnc') {
      try {
        const payload = {
          resourceId: resource.id,
          target: resource.target,
          user: resource.sshUsername || auth.user,
          protocol: resource.protocol,
          port: resource.port,
          justification: (accessMeta.justification || '').trim(),
          ticketId: (accessMeta.ticketId || '').trim(),
          purpose: (accessMeta.purpose || '').trim(),
          purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
          accessRequestId: accessMeta.accessRequestId || undefined
        };
        const created = await createSession(payload);
        setSessions((prev) => [created, ...prev]);
        if (created?.accessGrantId) {
          fetchAccessGrants()
            .then((data) => {
              setAccessGrants(Array.isArray(data?.items) ? data.items : []);
            })
            .catch(() => {});
        }
        setSessionError('');
        setInlineWebResource(null);
        setVncViewerSession(created);
        setMainTab('sessions');
        return true;
      } catch (error) {
        setSessionError(error.message || 'Unable to create session');
        return false;
      }
    }

    // Handle protocols that should use local TCP tunnel through the agent
    if (isAgentTunnelProtocol(resource.protocol)) {
      const randomPort = 10000 + Math.floor(Math.random() * 50000);
      const launchPayload = buildAgentLaunchPayload(resource, randomPort);
      setAgentModal({ resource, port: randomPort, copied: 'idle', linkCopied: 'idle', installCopied: 'idle', launchState: 'opening', ...launchPayload });
      launchAgentDeepLink(launchPayload.deepLink);
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
        purpose: (accessMeta.purpose || '').trim(),
        purposeEvidence: (accessMeta.purposeEvidence || '').trim(),
        accessRequestId: accessMeta.accessRequestId || undefined
      };
      const created = await createSession(payload);
      setSessions((prev) => [created, ...prev]);
      if (created?.accessGrantId) {
        fetchAccessGrants()
          .then((data) => {
            setAccessGrants(Array.isArray(data?.items) ? data.items : []);
          })
          .catch(() => {});
      }
      setSessionError('');
      setInlineWebResource(null);
      openTerminal(created);

      // Auto-inject credentials only for vaulted mode.
      if (resource.hasCredentials && (resource.credentialSource || 'vaulted') === 'vaulted') {
        try {
          const lease = await issueEphemeralCredential(resource.id);
          const creds = await consumeEphemeralCredential(lease.leaseId);
          if (creds.sshPassword) {
            setSshPassword(creds.sshPassword);
            setMainTab('sessions');
            setAutoConnectSessionId(created.id);
          }
        } catch (_) {
          // JIT-first: if lease issuance fails, fall back to manual password entry.
        }
      } else if ((resource.credentialSource || 'vaulted') !== 'vaulted') {
        setSshPassword('');
        setMainTab('sessions');
        setAutoConnectSessionId(created.id);
      }
      return true;
    } catch (error) {
      setSessionError(error.message || 'Unable to create session');
      return false;
    }
  };

  const closeAccessPrompt = () => {
    setAccessPromptResource(null);
    setAccessPromptReason('');
    setAccessPromptTicketId('');
    setAccessPromptPurpose('');
    setAccessPromptPurposeEvidence('');
    setAccessPromptMode('connect');
    setRiskPreview(null);
    setRiskPreviewError('');
  };

  const onConnectResource = async (resource) => {
    const protocol = String(resource?.protocol || '').toLowerCase();
    const sessionBackedProtocol = protocol !== 'http' && protocol !== 'https' && !isAgentTunnelProtocol(protocol);

    if (resource.requireDualApproval && !canManagePlatform) {
      const existingPlaybook =
        accessPlaybooks.find((item) => Number(item.resourceId) === Number(resource.id)) || null;
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
      setAccessPromptReason(existingPlaybook?.justification || '');
      setAccessPromptTicketId(existingPlaybook?.ticketId || '');
      setAccessPromptPurpose(existingPlaybook?.purpose || '');
      setAccessPromptPurposeEvidence(existingPlaybook?.purposeEvidence || '');
      setRiskPreview(null);
      setRiskPreviewError('');
      return;
    }

    if (sessionBackedProtocol) {
      const existingPlaybook =
        accessPlaybooks.find((item) => Number(item.resourceId) === Number(resource.id)) || null;
      setAccessPromptMode('connect');
      setAccessPromptResource(resource);
      setAccessPromptReason(existingPlaybook?.justification || '');
      setAccessPromptTicketId(existingPlaybook?.ticketId || '');
      setAccessPromptPurpose(existingPlaybook?.purpose || '');
      setAccessPromptPurposeEvidence(existingPlaybook?.purposeEvidence || '');
      setRiskPreview(null);
      setRiskPreviewError('');
      return;
    }
    await connectToResource(resource);
  };

  const openLiveSession = async (session) => {
    const protocol = String(session?.protocol || '').toLowerCase();
    if (protocol === 'vnc') {
      setVncViewerSession(session);
      setMainTab('sessions');
      return;
    }
    await openTerminal(session);
  };

  const applyCurrentAccessPlaybook = () => {
    if (!currentAccessPlaybook) {
      setSessionError(locale === 'fr' ? 'Aucun playbook enregistré pour cette ressource.' : 'No saved playbook for this resource.');
      return;
    }
    setAccessPromptReason(currentAccessPlaybook.justification || '');
    setAccessPromptTicketId(currentAccessPlaybook.ticketId || '');
    setAccessPromptPurpose(currentAccessPlaybook.purpose || '');
    setAccessPromptPurposeEvidence(currentAccessPlaybook.purposeEvidence || '');
    setSessionError('');
  };

  const saveCurrentAccessPlaybook = () => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return;
    const playbook = {
      resourceId,
      justification: accessPromptReason.trim(),
      ticketId: accessPromptTicketId.trim(),
      purpose: accessPromptPurpose.trim(),
      purposeEvidence: accessPromptPurposeEvidence.trim(),
      updatedAt: new Date().toISOString()
    };
    if (!playbook.justification && !playbook.ticketId && !playbook.purpose && !playbook.purposeEvidence) {
      setSessionError(locale === 'fr' ? 'Le playbook ne peut pas être vide. Remplissez au moins un champ avant enregistrement.' : 'Playbook cannot be empty. Fill at least one field before saving.');
      return;
    }
    setAccessPlaybooks((prev) => {
      const next = prev.filter((item) => Number(item.resourceId) !== resourceId);
      return [...next, playbook];
    });
    setSessionError('');
    setTerminalInfo(
      locale === 'fr'
        ? `Playbook d'accès enregistré pour ${accessPromptResource?.name || 'la ressource'}.`
        : `Access playbook saved for ${accessPromptResource?.name || 'resource'}.`
    );
  };

  const deleteCurrentAccessPlaybook = () => {
    const resourceId = Number(accessPromptResource?.id) || 0;
    if (!resourceId) return;
    setAccessPlaybooks((prev) => prev.filter((item) => Number(item.resourceId) !== resourceId));
    setSessionError('');
  };

  const onSubmitAccessPrompt = async (event) => {
    event.preventDefault();
    if (!accessPromptResource) {
      return;
    }
    const reason = accessPromptReason.trim();
    if (!reason) {
      setSessionError(
        containmentEnabled
          ? (locale === 'fr' ? "Une raison d'accès est requise tant que le mode confinement est actif." : 'Access reason is required while containment mode is active.')
          : (locale === 'fr' ? "Une raison d'accès est requise pour cette ressource." : 'Access reason is required for this resource.')
      );
      return;
    }
    const purpose = accessPromptPurpose.trim();
    const purposeEvidence = accessPromptPurposeEvidence.trim();
    const riskLevel = String(accessPromptResource.riskLevel || '').toLowerCase();
    const purposeRequired = riskLevel === 'high' || riskLevel === 'critical';
    if (purposeRequired && !purpose) {
      setSessionError(locale === 'fr' ? 'Les ressources à haut risque exigent un objectif.' : 'High-risk resources require a purpose.');
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
        setSessionError(locale === 'fr' ? "Demande d'accès envoyée. Attendez l'approbation d'un admin." : 'Access request submitted. Wait for admin approval.');
        closeAccessPrompt();
        return;
      } catch (error) {
        setSessionError(error.message || (locale === 'fr' ? "Impossible d'envoyer la demande d'accès" : 'Unable to submit access request'));
        return;
      }
    }
    const connected = await connectToResource(accessPromptResource, {
      justification: reason,
      ticketId: accessPromptTicketId.trim(),
      purpose,
      purposeEvidence
    });
    if (connected) {
      closeAccessPrompt();
    }
  };

  useEffect(() => {
    if (!accessPromptResource || !auth.token) {
      setRiskPreview(null);
      setRiskPreviewError('');
      return undefined;
    }
    const timer = window.setTimeout(async () => {
      setRiskPreviewLoading(true);
      try {
        const data = await previewSessionRisk({
          resourceId: accessPromptResource.id,
          justification: accessPromptReason.trim(),
          ticketId: accessPromptTicketId.trim(),
          purpose: accessPromptPurpose.trim()
        });
        setRiskPreview(data);
        setRiskPreviewError('');
      } catch (error) {
        setRiskPreview(null);
        setRiskPreviewError(error.message || (locale === 'fr' ? "Impossible de calculer l'aperçu de risque" : 'Unable to compute risk preview'));
      } finally {
        setRiskPreviewLoading(false);
      }
    }, 220);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    accessPromptResource,
    accessPromptReason,
    accessPromptTicketId,
    accessPromptPurpose,
    auth.token
  ]);

  const onOpenSessionDna = async (sessionId) => {
    setSessionDnaLoading(true);
    setSessionDnaError('');
    setSessionDna(null);
    try {
      const data = await fetchSessionDna(sessionId);
      setSessionDna(data);
    } catch (error) {
      setSessionDnaError(error.message || (locale === 'fr' ? "Impossible de charger l'ADN de session" : 'Unable to load session DNA'));
    } finally {
      setSessionDnaLoading(false);
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
      setAccessRequestError(error.message || (locale === 'fr' ? "Impossible d'approuver la demande d'accès" : 'Unable to approve access request'));
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
      setAccessRequestError(error.message || (locale === 'fr' ? "Impossible de refuser la demande d'accès" : 'Unable to deny access request'));
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
      setResourceError(locale === 'fr' ? 'Le nom, la cible et le protocole sont requis.' : 'Name, target and protocol are required.');
      return;
    }

    const payload = {
      name: trimmedName,
      target: trimmedTarget,
      protocol: selectedProtocol,
      port: Number.parseInt(resourceForm.port, 10) || 22,
      tunnelTicketRateLimitMaxAttempts: Math.max(
        0,
        Number.parseInt(resourceForm.tunnelTicketRateLimitMaxAttempts, 10) || 0
      ),
      description: resourceForm.description.trim(),
      imageUrl: resourceForm.imageUrl.trim(),
      imageData: resourceForm.imageData || '',
      tagsCsv: resourceForm.tagsCsv.trim(),
      credentialSource: resourceForm.credentialSource || 'vaulted',
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
        tunnelTicketRateLimitMaxAttempts: '0',
        description: '',
        imageUrl: '',
        imageData: '',
        tagsCsv: '',
        credentialSource: 'vaulted',
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
      setResourceError(error.message || t('feedback.unableSaveResource'));
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
      tunnelTicketRateLimitMaxAttempts: String(
        Math.max(0, Number(resource.tunnelTicketRateLimitMaxAttempts) || 0)
      ),
      description: resource.description || '',
      imageUrl: resource.imageUrl || '',
      imageData: resource.imageData || '',
      tagsCsv: resource.tagsCsv || '',
      credentialSource: resource.credentialSource || 'vaulted',
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
      setResourceError(error.message || t('feedback.unableDeleteResource'));
    }
  };

  const resetAccessPolicyForm = () => {
    setEditingAccessPolicyId(null);
    setAccessPolicyForm({
      name: '',
      description: '',
      identityPattern: '',
      groupName: '',
      role: '',
      resourceTagsCsv: '',
      riskLevel: 'any',
      ticketRequired: false,
      requireJustification: false,
      approvalMode: 'inherit',
      mfaRequirement: 'any',
      timeWindow: 'any',
      maxDurationSeconds: '3600',
      routingConstraint: 'any',
      enabled: true
    });
  };

  const onSubmitAccessPolicy = async (event) => {
    event.preventDefault();
    const payload = {
      name: accessPolicyForm.name.trim(),
      description: accessPolicyForm.description.trim(),
      identityPattern: accessPolicyForm.identityPattern.trim(),
      groupName: accessPolicyForm.groupName.trim(),
      role: accessPolicyForm.role.trim(),
      resourceTagsCsv: accessPolicyForm.resourceTagsCsv.trim(),
      riskLevel: accessPolicyForm.riskLevel || 'any',
      ticketRequired: !!accessPolicyForm.ticketRequired,
      requireJustification: !!accessPolicyForm.requireJustification,
      approvalMode: accessPolicyForm.approvalMode || 'inherit',
      mfaRequirement: accessPolicyForm.mfaRequirement || 'any',
      timeWindow: accessPolicyForm.timeWindow.trim() || 'any',
      maxDurationSeconds: Number.parseInt(accessPolicyForm.maxDurationSeconds, 10) || 3600,
      routingConstraint: accessPolicyForm.routingConstraint || 'any',
      enabled: !!accessPolicyForm.enabled
    };
    try {
      const saved = editingAccessPolicyId
        ? await updateAccessPolicy(editingAccessPolicyId, payload)
        : await createAccessPolicy(payload);
      setAccessPolicies((prev) => {
        if (editingAccessPolicyId) {
          return prev.map((item) => (item.id === editingAccessPolicyId ? saved : item));
        }
        return [...prev, saved];
      });
      setAccessPolicyError('');
      resetAccessPolicyForm();
    } catch (error) {
      setAccessPolicyError(error.message || 'Unable to save access policy');
    }
  };

  const onEditAccessPolicy = (policy) => {
    setEditingAccessPolicyId(policy.id);
    setAccessPolicyForm({
      name: policy.name || '',
      description: policy.description || '',
      identityPattern: policy.identityPattern || '',
      groupName: policy.groupName || '',
      role: policy.role || '',
      resourceTagsCsv: policy.resourceTagsCsv || '',
      riskLevel: policy.riskLevel || 'any',
      ticketRequired: !!policy.ticketRequired,
      requireJustification: !!policy.requireJustification,
      approvalMode: policy.approvalMode || 'inherit',
      mfaRequirement: policy.mfaRequirement || 'any',
      timeWindow: policy.timeWindow || 'any',
      maxDurationSeconds: String(policy.maxDurationSeconds || 3600),
      routingConstraint: policy.routingConstraint || 'any',
      enabled: !!policy.enabled
    });
  };

  const onDeleteAccessPolicy = async (policyId) => {
    try {
      await deleteAccessPolicy(policyId);
      setAccessPolicies((prev) => prev.filter((item) => item.id !== policyId));
      setAccessPolicyError('');
      if (editingAccessPolicyId === policyId) resetAccessPolicyForm();
    } catch (error) {
      setAccessPolicyError(error.message || 'Unable to delete access policy');
    }
  };

  const resetAccessProfileForm = () => {
    setEditingAccessProfileId(null);
    setAccessProfileForm({
      name: '',
      description: '',
      resourceTagsCsv: '',
      resourceIdsCsv: '',
      policyId: '0'
    });
  };

  const onSubmitAccessProfile = async (event) => {
    event.preventDefault();
    const payload = {
      name: accessProfileForm.name.trim(),
      description: accessProfileForm.description.trim(),
      resourceTagsCsv: accessProfileForm.resourceTagsCsv.trim(),
      resourceIdsCsv: accessProfileForm.resourceIdsCsv.trim(),
      policyId: Number.parseInt(accessProfileForm.policyId, 10) || 0
    };
    try {
      const saved = editingAccessProfileId
        ? await updateAccessProfile(editingAccessProfileId, payload)
        : await createAccessProfile(payload);
      setAccessProfiles((prev) => {
        if (editingAccessProfileId) {
          return prev.map((item) => (item.id === editingAccessProfileId ? saved : item));
        }
        return [...prev, saved];
      });
      setAccessProfileError('');
      resetAccessProfileForm();
    } catch (error) {
      setAccessProfileError(error.message || 'Unable to save access profile');
    }
  };

  const onEditAccessProfile = (profile) => {
    setEditingAccessProfileId(profile.id);
    setAccessProfileForm({
      name: profile.name || '',
      description: profile.description || '',
      resourceTagsCsv: profile.resourceTagsCsv || '',
      resourceIdsCsv: profile.resourceIdsCsv || '',
      policyId: String(profile.policyId || 0)
    });
  };

  const onDeleteAccessProfile = async (profileId) => {
    try {
      await deleteAccessProfile(profileId);
      setAccessProfiles((prev) => prev.filter((item) => item.id !== profileId));
      setAccessProfileError('');
      if (editingAccessProfileId === profileId) resetAccessProfileForm();
    } catch (error) {
      setAccessProfileError(error.message || 'Unable to delete access profile');
    }
  };

  const onOpenSessionEvidence = async (sessionId) => {
    setSessionEvidenceLoading(true);
    setSessionEvidencePack(null);
    setSessionEvidenceError('');
    try {
      const data = await fetchSessionEvidencePack(sessionId);
      setSessionEvidencePack(data);
    } catch (error) {
      setSessionEvidenceError(error.message || 'Unable to load evidence pack');
    } finally {
      setSessionEvidenceLoading(false);
    }
  };

  const onSubmitUser = async (event) => {
    event.preventDefault();
    setUserError('');
    const payload = {
      username: userForm.username.trim(),
      password: userForm.password,
      role: userForm.role,
      forcePasswordRotation: !!userForm.forcePasswordRotation
    };
    try {
      if (editingUserId) {
        const updated = await updateUser(editingUserId, {
          password: payload.password,
          role: payload.role,
          forcePasswordRotation: payload.forcePasswordRotation
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
        role: 'operator',
        forcePasswordRotation: false
      });
    } catch (error) {
      setUserError(error.message || t('feedback.unableSaveUser'));
    }
  };

  const onEditUser = (user) => {
    setEditingUserId(user.id);
    setUserForm({
      username: user.username || '',
      password: '',
      role: user.role || 'operator',
      forcePasswordRotation: !!user.bootstrapPasswordChangeRequired
    });
  };

  const onDeleteUser = async (userId) => {
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((item) => item.id !== userId));
    } catch (error) {
      setUserError(error.message || t('feedback.unableDeleteUser'));
    }
  };

  const onLoadUserPermissions = async (user) => {
    try {
      setLoadingAccessScope(true);
      setSelectedUserForAccessScope(user);
      const [resourceResponse, profileResponse] = await Promise.all([
        getUserResourcePermissions(user.id),
        getUserAccessProfiles(user.id)
      ]);
      setUserResourceScope(resourceResponse.resourceIds || []);
      setUserAccessProfiles(profileResponse.profileIds || []);
      setAccessScopeError('');
    } catch (error) {
      setAccessScopeError(error.message || t('feedback.unableLoadAccessScope'));
    } finally {
      setLoadingAccessScope(false);
    }
  };

  const onToggleResourcePermission = async (resourceId) => {
    if (!selectedUserForAccessScope) return;
    
    const hasPermission = userResourceScope.includes(resourceId);
    try {
      if (hasPermission) {
        await revokeResourcePermission(selectedUserForAccessScope.id, resourceId);
        setUserResourceScope((prev) => prev.filter((id) => id !== resourceId));
      } else {
        await grantResourcePermission(selectedUserForAccessScope.id, resourceId);
        setUserResourceScope((prev) => [...prev, resourceId]);
      }
      setAccessScopeError('');
    } catch (error) {
      setAccessScopeError(error.message || t('feedback.unableModifyResourceScope'));
    }
  };

  const onToggleAccessProfile = async (profileId) => {
    if (!selectedUserForAccessScope) return;
    const hasProfile = userAccessProfiles.includes(profileId);
    try {
      if (hasProfile) {
        await revokeAccessProfile(selectedUserForAccessScope.id, profileId);
        setUserAccessProfiles((prev) => prev.filter((id) => id !== profileId));
      } else {
        await grantAccessProfile(selectedUserForAccessScope.id, profileId);
        setUserAccessProfiles((prev) => [...prev, profileId]);
      }
      const refreshedResources = await getUserResourcePermissions(selectedUserForAccessScope.id);
      setUserResourceScope(refreshedResources.resourceIds || []);
      setAccessScopeError('');
    } catch (error) {
      setAccessScopeError(error.message || 'Unable to modify access profile assignment');
    }
  };

  const refreshRelayBindings = async () => {
    const resourceList = Array.isArray(resources) ? resources : [];
    const next = {};
    await Promise.all(
      resourceList.map(async (resource) => {
        try {
          const data = await fetchRelayResolution(resource.id);
          next[resource.id] = data?.relay?.relayId || '';
        } catch (_) {}
      })
    );
    setRelayBindings(next);
  };

  const onAssignRelay = async (resourceId, relayId) => {
    const normalizedResourceId = Number(resourceId) || 0;
    if (!normalizedResourceId || relayAssignBusyResourceId) return;
    setRelayAssignBusyResourceId(normalizedResourceId);
    try {
      const selectedRelayId = String(relayId || '').trim();
      if (selectedRelayId) {
        await assignRelayToResource(normalizedResourceId, selectedRelayId);
      } else {
        await clearRelayForResource(normalizedResourceId);
      }
      setRelayBindings((prev) => ({
        ...prev,
        [normalizedResourceId]: selectedRelayId
      }));
      setRelayError('');
    } catch (error) {
      setRelayError(error.message || t('feedback.unableUpdateRelayAssignment'));
    } finally {
      setRelayAssignBusyResourceId(0);
    }
  };

  const onIssueRelayEnrollmentToken = async () => {
    if (issuingRelayEnrollmentToken) return;
    setIssuingRelayEnrollmentToken(true);
    setRelayEnrollmentCopyStatus('');
    try {
      const data = await createRelayEnrollmentToken({
        ttlSeconds: relayConfig.enrollmentTokenTtlSeconds
      });
      setRelayEnrollmentToken(String(data?.enrollmentToken || ''));
      setRelayEnrollmentTokenExpiresAt(String(data?.expiresAt || ''));
      setRelayError('');
    } catch (error) {
      setRelayError(error.message || t('feedback.unableIssueRelayToken'));
    } finally {
      setIssuingRelayEnrollmentToken(false);
    }
  };

  const onIssueRelayCertificate = async () => {
    if (issuingRelayCertificate) return;
    setIssuingRelayCertificate(true);
    setRelayCertificateCopyStatus('');
    try {
      const data = await createRelayCertificate({
        ttlSeconds: relayConfig.certificateTtlSeconds
      });
      setRelayCertificate(String(data?.certificate || ''));
      setRelayCertificateId(String(data?.certificateId || ''));
      setRelayCertificateExpiresAt(String(data?.expiresAt || ''));
      setRelayError('');
    } catch (error) {
      setRelayError(error.message || t('feedback.unableIssueRelayCertificate'));
    } finally {
      setIssuingRelayCertificate(false);
    }
  };

  const onCopyRelayCertificate = async () => {
    if (!relayCertificate) return;
    try {
      await navigator.clipboard.writeText(relayCertificate);
      setRelayCertificateCopyStatus(t('feedback.certificateCopied'));
    } catch (_) {
      setRelayCertificateCopyStatus(t('feedback.copyFailed'));
    }
  };

  const onCopyRelayEnrollmentToken = async () => {
    if (!relayEnrollmentToken) return;
    try {
      await navigator.clipboard.writeText(relayEnrollmentToken);
      setRelayEnrollmentCopyStatus(t('feedback.tokenCopied'));
    } catch (_) {
      setRelayEnrollmentCopyStatus(t('feedback.copyFailed'));
    }
  };

  // ── 2FA handlers ──

  const onSetup2FA = async () => {
    setTotpError('');
    setTotpCopyStatus('');
    try {
      const data = await setup2FA();
      setTotpSetupData(data);
    } catch (error) {
      setTotpError(error.message || t('feedback.failedSetup2fa'));
    }
  };

  const onVerify2FA = async () => {
    setTotpError('');
    try {
      const data = await verify2FA(totpSetupCode);
      setTotpEnabled(true);
      setWebauthnEnabled(!!data.webauthnEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setTotpSetupData(null);
      setTotpQrDataUrl('');
      setTotpSetupCode('');
      setTotpError('');
      setTotpCopyStatus('');
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: true,
        webauthnEnabled: !!data.webauthnEnabled
      });
    } catch (error) {
      setTotpError(error.message || t('feedback.invalidCode'));
    }
  };

  const onDisable2FA = async () => {
    setTotpError('');
    try {
      const data = await disable2FA(totpDisableCode);
      setTotpEnabled(false);
      setWebauthnEnabled(!!data.webauthnEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setTotpDisableCode('');
      setTotpError('');
      setBootstrapState((prev) => ({
        ...prev,
        mfaSetupRequired: !data.webauthnEnabled,
        totpEnabled: false,
        webauthnEnabled: !!data.webauthnEnabled
      }));
    } catch (error) {
      setTotpError(error.message || t('feedback.invalidCode'));
    }
  };

  const onLoad2FAStatus = async () => {
    try {
      const data = await get2FAStatus();
      setTotpEnabled(!!data.totpEnabled);
      setWebauthnEnabled(!!data.webauthnEnabled);
      setWebauthnCredentials(Array.isArray(data.credentials) ? data.credentials : []);
      setPreferredMfaMethod(String(data.preferredMfaMethod || 'any'));
      setBootstrapState((prev) => ({
        ...prev,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      }));
    } catch (_) {}
  };

  useEffect(() => {
    if (auth.token) onLoad2FAStatus();
  }, [auth.token]);

  const onCopyTotpValue = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value || '');
      setTotpCopyStatus(t('feedback.copiedLabel', { label }));
    } catch (_) {
      setTotpCopyStatus(t('feedback.unableCopyLabel', { label: String(label || '').toLowerCase() }));
    }
  };

  const onRegisterPasskey = async (label = '') => {
    setTotpError('');
    setWebauthnBusy(true);
    try {
      const options = await beginWebAuthnRegistration({ label });
      const registration = await createBrowserPasskey(options);
      const data = await verifyWebAuthnRegistration({
        requestId: options.requestId,
        label,
        ...registration
      });
      setWebauthnEnabled(!!data.webauthnEnabled);
      setTotpEnabled(!!data.totpEnabled);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      await onLoad2FAStatus();
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      });
      setWebauthnLabel('');
    } catch (error) {
      const message = error.message || t('feedback.failedRegisterPasskey');
      if (message.toLowerCase().includes('valid domain')) {
        setTotpError(`${message} ${t('feedback.currentOrigin', { value: window.location.origin })}`);
      } else {
        setTotpError(message);
      }
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onDeletePasskey = async (credentialId) => {
    setTotpError('');
    setWebauthnBusy(true);
    try {
      const data = await deleteWebAuthnCredential(credentialId);
      setWebauthnEnabled(!!data.webauthnEnabled);
      setTotpEnabled(!!data.totpEnabled);
      setWebauthnCredentials(Array.isArray(data.credentials) ? data.credentials : []);
      if (data.preferredMfaMethod) setPreferredMfaMethod(String(data.preferredMfaMethod));
      setBootstrapState((prev) => ({
        ...prev,
        mfaSetupRequired: !data.totpEnabled && !data.webauthnEnabled,
        totpEnabled: !!data.totpEnabled,
        webauthnEnabled: !!data.webauthnEnabled
      }));
    } catch (error) {
      setTotpError(error.message || t('feedback.failedRemovePasskey'));
    } finally {
      setWebauthnBusy(false);
    }
  };

  const onUpdateMfaPreference = async (method) => {
    setTotpError('');
    try {
      const data = await setMfaPreference(method);
      setPreferredMfaMethod(String(data.preferredMfaMethod || method || 'any'));
    } catch (error) {
      setTotpError(error.message || t('feedback.failedSaveMfaPreference'));
    }
  };

  useEffect(() => {
    if (!auth.token) {
      setBootstrapState({
        required: false,
        passwordChangeRequired: false,
        mfaSetupRequired: false,
        totpEnabled: false,
        webauthnEnabled: false
      });
      setWebauthnEnabled(false);
      setWebauthnCredentials([]);
      return;
    }
    let active = true;
    fetchBootstrapStatus()
      .then((data) => {
        if (!active) return;
        const bootstrap = data.bootstrap || {};
        setBootstrapState({
          required: !!bootstrap.required,
          passwordChangeRequired: !!bootstrap.passwordChangeRequired,
          mfaSetupRequired: !!bootstrap.mfaSetupRequired,
          totpEnabled: !!bootstrap.totpEnabled,
          webauthnEnabled: !!bootstrap.webauthnEnabled
        });
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [auth.token]);

  useEffect(() => {
    if (!editingUserId) {
      setUserForm((prev) => {
        const nextValue = prev.role === 'admin' ? true : prev.forcePasswordRotation;
        if (nextValue === prev.forcePasswordRotation) {
          return prev;
        }
        return {
          ...prev,
          forcePasswordRotation: nextValue
        };
      });
    }
  }, [editingUserId, userForm.role]);

  useEffect(() => {
    let active = true;
    if (!totpSetupData?.otpauthUri) {
      setTotpQrDataUrl('');
      return;
    }
    QRCode.toDataURL(totpSetupData.otpauthUri, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 220
    })
      .then((url) => {
        if (active) {
          setTotpQrDataUrl(url);
        }
      })
      .catch(() => {
        if (active) {
          setTotpQrDataUrl('');
        }
      });
    return () => {
      active = false;
    };
  }, [totpSetupData]);

  useEffect(() => {
    if (!auth.token || !canManagePlatform || !resources.length) {
      setRelayBindings({});
      return;
    }
    refreshRelayBindings().catch(() => {
      setRelayError(t('feedback.unableResolveRelayBindings'));
    });
  }, [auth.token, canManagePlatform, resources]);

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
      setRecordingsError(error.message || t('feedback.unableLoadRecordings'));
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
      setRecordingsError(error.message || t('feedback.unableLoadRecording'));
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
        terminal.writeln(`\x1b[33m${t('feedback.shadowConnected', { id: session.id })}\x1b[0m`);
        terminal.writeln('');
      });

      socket.addEventListener('message', (event) => {
        if (typeof event.data === 'string') {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'status') {
              terminal.writeln(`\x1b[36m${t('feedback.shadowInfo', { message: payload.message })}\x1b[0m`);
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
      setChangePwError(t('feedback.passwordsDoNotMatch'));
      return;
    }
    try {
      const data = await changePassword(changePwCurrent, changePwNew, {
        keepCurrentSession: bootstrapRequired
      });
      setChangePwSuccess(
        bootstrapRequired
          ? t('feedback.passwordUpdatedContinueMfa')
          : t('feedback.passwordChanged')
      );
      setChangePwCurrent('');
      setChangePwNew('');
      setChangePwConfirm('');
      const bootstrap = data.bootstrap || {};
      setBootstrapState({
        required: !!bootstrap.required,
        passwordChangeRequired: !!bootstrap.passwordChangeRequired,
        mfaSetupRequired: !!bootstrap.mfaSetupRequired,
        totpEnabled,
        webauthnEnabled
      });
      if (!bootstrapRequired) {
        setBootstrapState({
          required: false,
          passwordChangeRequired: false,
          mfaSetupRequired: false,
          totpEnabled,
          webauthnEnabled
        });
      }
    } catch (error) {
      setChangePwError(error.message || t('feedback.failedChangePassword'));
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

  const watchedSessions = useMemo(() => {
    const watched = sortedSessions.filter((session) =>
      watchedSessionIds.includes(Number(session.id))
    );
    return watched.slice(0, 8);
  }, [sortedSessions, watchedSessionIds]);

  const sessionSlo = useMemo(() => {
    const total = sessions.length;
    const active = sessions.filter((item) => item.status === 'active').length;
    const terminated = sessions.filter((item) => item.status === 'terminated').length;
    const completionRate = total > 0 ? Math.round((terminated / total) * 100) : 0;

    const closedDurationsMin = sessions
      .map((item) => {
        const opened = Date.parse(item.createdAt || '') || 0;
        const closed = Date.parse(item.terminatedAt || '') || 0;
        if (!opened || !closed || closed <= opened) return null;
        return (closed - opened) / 60000;
      })
      .filter((value) => Number.isFinite(value));

    const avgDurationMin = closedDurationsMin.length
      ? Math.round(closedDurationsMin.reduce((sum, value) => sum + value, 0) / closedDurationsMin.length)
      : 0;

    const staleActive = sessions.filter((item) => {
      if (item.status !== 'active') return false;
      const opened = Date.parse(item.createdAt || '') || 0;
      if (!opened) return false;
      return opened < Date.now() - 4 * 60 * 60 * 1000;
    }).length;

    return {
      total,
      active,
      terminated,
      completionRate,
      avgDurationMin,
      staleActive
    };
  }, [sessions]);

  useEffect(() => {
    if (!watchedSessionIds.length) {
      watchlistStatusRef.current = {};
      return;
    }
    const nextStatus = {};
    const nextAlerts = [];
    watchedSessionIds.forEach((sessionId) => {
      const found = sessions.find((item) => Number(item.id) === Number(sessionId));
      if (!found) return;
      const normalizedStatus = String(found.status || 'unknown').toLowerCase();
      nextStatus[String(sessionId)] = normalizedStatus;
      const previous = watchlistStatusRef.current[String(sessionId)];
      if (previous && previous !== normalizedStatus) {
        nextAlerts.push({
          key: `watch:${sessionId}:${Date.now()}`,
          sessionId,
          status: normalizedStatus,
          message: t('feedback.sessionStatusChanged', { id: sessionId, from: previous, to: normalizedStatus }),
          createdAt: new Date().toISOString()
        });
      }
    });
    watchlistStatusRef.current = nextStatus;
    if (nextAlerts.length) {
      setWatchlistAlerts((prev) => [...nextAlerts, ...prev].slice(0, 6));
    }
  }, [sessions, watchedSessionIds]);

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
        severity: (totpEnabled || webauthnEnabled) ? 'ok' : 'warning',
        title: 'MFA posture',
        value: (totpEnabled || webauthnEnabled) ? 'enabled' : 'disabled',
        hint: webauthnEnabled
          ? 'Your account is protected with a passkey or hardware security key.'
          : totpEnabled
            ? 'Your account is protected with TOTP.'
            : 'Enable TOTP or a passkey to strengthen operator authentication.'
      }
    ];
  }, [securityAuditItems, activeSessions, totpEnabled, webauthnEnabled]);

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

  const toCsvCell = (value) => {
    const raw = String(value ?? '');
    // Neutralize CSV formula injection: a cell starting with = + - @ (or a
    // leading tab/CR) is interpreted as a formula by Excel/Sheets, even when
    // quoted. Prefix such values with a single quote so they stay literal.
    const guarded = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
    const escaped = guarded.replace(/"/g, '""');
    return `"${escaped}"`;
  };

  const exportFilteredAuditCsv = () => {
    if (!filteredAuditItems.length) {
      setAuditError(t('app.noAuditEvents'));
      return;
    }

    const header = ['id', 'type', 'actor', 'createdAt', 'detail'];
    const rows = filteredAuditItems.map((item) => [
      item.id,
      item.type,
      item.actor,
      item.createdAt,
      renderAuditDetail(item) || ''
    ]);
    const csvLines = [header, ...rows].map((row) => row.map(toCsvCell).join(','));
    const csvPayload = `\uFEFF${csvLines.join('\n')}`;

    const blob = new Blob([csvPayload], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit-export-${stamp}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setAuditError('');
  };

  const formatRelativeDate = (value) => {
    const timestamp = Date.parse(value || '');
    if (!timestamp) return value || t('common.notAvailable');
    const diffSec = Math.floor((Date.now() - timestamp) / 1000);
    if (diffSec < 60) return t('time.justNow');
    if (diffSec < 3600) return t('time.minutesAgo', { count: Math.floor(diffSec / 60) });
    if (diffSec < 86400) return t('time.hoursAgo', { count: Math.floor(diffSec / 3600) });
    return t('time.daysAgo', { count: Math.floor(diffSec / 86400) });
  };

  const renderBootstrapOverlay = () => {
    if (!bootstrapRequired) return null;
    const currentStep = bootstrapState.passwordChangeRequired
      ? t('bootstrap.changeDefaultPassword')
      : t('bootstrap.enableMfa');
    return (
      <div className="modal-overlay bootstrap-overlay">
        <div className="modal-content bootstrap-modal" onClick={(event) => event.stopPropagation()}>
          <p className="workflow-kicker">{t('bootstrap.title')}</p>
          <h3>{t('bootstrap.heading')}</h3>
          <p className="muted">
            {t('bootstrap.body')}
          </p>
          <div className="bootstrap-checklist">
            <div className={`bootstrap-step ${bootstrapState.passwordChangeRequired ? 'active' : 'done'}`}>
              <strong>1. {t('bootstrap.step1')}</strong>
              <span>{bootstrapState.passwordChangeRequired ? t('bootstrap.requiredNow') : t('bootstrap.done')}</span>
            </div>
            <div className={`bootstrap-step ${!bootstrapState.passwordChangeRequired && bootstrapState.mfaSetupRequired ? 'active' : ''} ${!bootstrapState.mfaSetupRequired ? 'done' : ''}`}>
              <strong>2. {t('bootstrap.step2')}</strong>
              <span>{bootstrapState.mfaSetupRequired ? t('bootstrap.pending') : t('bootstrap.done')}</span>
            </div>
          </div>
          <p className="bootstrap-status">{t('bootstrap.currentStep', { step: currentStep })}</p>
          {bootstrapState.passwordChangeRequired ? (
            <form onSubmit={onChangePassword}>
              <label>
                {t('auth.currentPassword')}
                <input
                  type="password"
                  value={changePwCurrent}
                  onChange={(e) => setChangePwCurrent(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </label>
              <label>
                {t('bootstrap.newAdminPassword')}
                <input
                  type="password"
                  value={changePwNew}
                  onChange={(e) => setChangePwNew(e.target.value)}
                  required
                  autoComplete="new-password"
                  placeholder={t('auth.passwordPlaceholder')}
                />
              </label>
              <label>
                {t('auth.confirmNewPassword')}
                <input
                  type="password"
                  value={changePwConfirm}
                  onChange={(e) => setChangePwConfirm(e.target.value)}
                  required
                  autoComplete="new-password"
                />
              </label>
              {changePwError && <p className="error">{changePwError}</p>}
              {changePwSuccess && <p className="success">{changePwSuccess}</p>}
              <div className="bootstrap-actions">
                <button type="submit">{t('auth.saveNewPassword')}</button>
              </div>
            </form>
          ) : (
            <div className="bootstrap-mfa-block">
              {totpError && <p className="error">{totpError}</p>}
              {!totpEnabled && !totpSetupData && (
                <>
                  <p className="muted">
                    {t('bootstrap.finishHardening')}
                  </p>
                  <div className="bootstrap-actions">
                    <button type="button" onClick={onSetup2FA}>{t('bootstrap.startMfaSetup')}</button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => onRegisterPasskey('Admin security key')}
                      disabled={webauthnBusy || !isWebAuthnSupported()}
                    >
                      {webauthnBusy ? t('admin.registering') : t('auth.usePasskey')}
                    </button>
                  </div>
                  {!isWebAuthnSupported() && (
                    <p className="muted">
                      {t('bootstrap.passkeyBrowserHint')}
                    </p>
                  )}
                </>
              )}
              {totpSetupData && (
                <div className="bootstrap-totp-panel">
                  <p>
                    {t('bootstrap.totpHelp')}
                  </p>
                  {totpQrDataUrl && (
                    <div className="bootstrap-qr-image-card">
                      <img src={totpQrDataUrl} alt={t('bootstrap.qrAlt')} width={220} height={220} />
                    </div>
                  )}
                  <div className="bootstrap-qr-card">
                    <strong>{t('bootstrap.manualSecret')}</strong>
                    <code className="inline-secret">{totpSetupData.secret}</code>
                    <div className="bootstrap-actions">
                      <button type="button" className="ghost" onClick={() => onCopyTotpValue(totpSetupData.secret, t('bootstrap.manualSecret'))}>
                        {t('bootstrap.copySecret')}
                      </button>
                      <button type="button" className="ghost" onClick={() => onCopyTotpValue(totpSetupData.otpauthUri, t('bootstrap.enrollmentUri'))}>
                        {t('bootstrap.copyUri')}
                      </button>
                    </div>
                  </div>
                  {totpCopyStatus && <p className="muted">{totpCopyStatus}</p>}
                  <label>
                    {t('auth.authenticatorCode')}
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={totpSetupCode}
                      onChange={(e) => setTotpSetupCode(e.target.value)}
                      placeholder="123456"
                    />
                  </label>
                  <div className="bootstrap-actions">
                    <button type="button" onClick={onVerify2FA}>{t('bootstrap.verifyAndEnableMfa')}</button>
                  </div>
                </div>
              )}
              {(totpEnabled || webauthnEnabled) && !bootstrapState.mfaSetupRequired && (
                <p className="success">{t('bootstrap.mfaEnabled')}</p>
              )}
            </div>
          )}
        </div>
      </div>
    );
  };

  const renderLogin = () => (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo-wrapper">
          <img src="/assets/logo-full-blue.png" alt="EndoriumFort" className="login-logo" />
        </div>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
          <h1>{t('auth.signIn')}</h1>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <select aria-label={t('common.language')} value={locale} onChange={(event) => setLocale(event.target.value)}>
              <option value="fr">{t('common.french')}</option>
              <option value="en">{t('common.english')}</option>
            </select>
            <button type="button" className="ghost icon-btn" title={darkMode ? t('auth.lightMode') : t('auth.darkMode')} onClick={toggleDarkMode}>
              {darkMode ? '☀️' : '🌙'}
            </button>
          </div>
        </div>
        <p className="muted">
          {t('auth.accessConsole')}
        </p>
        <form className="auth-form" onSubmit={onLogin}>
          <label>
            {t('auth.user')}
            <input
              name="user"
              value={auth.user}
              onChange={onAuthChange}
              placeholder="ops-admin"
              disabled={twoFARequired}
            />
          </label>
          <label>
            {t('auth.password')}
            <input
              name="password"
              type="password"
              value={auth.password}
              onChange={onAuthChange}
              placeholder={t('auth.password')}
              disabled={twoFARequired}
            />
          </label>
          {twoFARequired && (
            <div className="login-mfa-block">
              {availableMfaMethods.includes('totp') && (
                <label>
                  {t('auth.authenticatorCode6Digits')}
                  <input
                    className="mfa-code-input login-mfa-code"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    placeholder="123456"
                    autoFocus
                  />
                </label>
              )}
              {availableMfaMethods.includes('webauthn') && (
                <div className="mfa-panel-block login-passkey-card">
                  <p className="muted">
                    {t('auth.usePasskey')}
                  </p>
                  <button
                    type="button"
                    className="ghost"
                    onClick={onLoginWithPasskey}
                    disabled={webauthnBusy || !webauthnLoginOptions}
                  >
                    {webauthnBusy ? t('auth.waitingForSecurityKey') : t('auth.usePasskey')}
                  </button>
                </div>
              )}
            </div>
          )}
          <button type="submit">
            {twoFARequired ? t('auth.verifyAndSignIn') : t('auth.signIn')}
          </button>
          {!twoFARequired && (
            <button type="button" className="ghost" onClick={onStartSsoLogin}>
              {locale === 'fr' ? 'Se connecter via SSO (OIDC)' : 'Sign in with SSO (OIDC)'}
            </button>
          )}
          {twoFARequired && (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setTwoFARequired(false);
                setTotpCode('');
                setAvailableMfaMethods([]);
                setWebauthnLoginOptions(null);
                setAuthError('');
              }}
            >
              {t('common.back')}
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
            <h1>{t('admin.console')}</h1>
          </div>
        </div>
        <div className="top-actions">
          <select aria-label={t('common.language')} value={locale} onChange={(event) => setLocale(event.target.value)}>
            <option value="fr">{t('common.french')}</option>
            <option value="en">{t('common.english')}</option>
          </select>
          <button type="button" className="ghost icon-btn" title={darkMode ? t('auth.lightMode') : t('auth.darkMode')} onClick={toggleDarkMode}>
            {darkMode ? '☀️' : '🌙'}
          </button>
          <button type="button" className="ghost" onClick={() => navigate('/')}
          >
            {t('auth.backToConsole')}
          </button>
          <button type="button" className="secondary" onClick={onLogout}>
            {t('auth.signOut')}
          </button>
        </div>
      </header>

      {canManagePlatform && (
        <>
          {stats && (
            <section className="metric-tile-grid reveal" style={{ marginBottom: '1rem' }}>
              <MetricTile tone="sessions" label={t('app.activeCount', { count: '' }).trim()} value={stats.sessions?.active || 0} />
              <MetricTile tone="total" label={t('app.totalSessions')} value={stats.sessions?.total || 0} />
              <MetricTile tone="resources" label={t('admin.resources')} value={stats.resources?.total || 0} />
              <MetricTile tone="users" label={t('admin.users')} value={stats.users?.total || 0} />
              <MetricTile tone="recordings" label={t('app.recordings')} value={stats.recordings?.total || 0} />
              <MetricTile tone="tokens" label={t('app.activeTokens')} value={stats.auth?.activeTokens || 0} />
            </section>
          )}

          <section className="admin-shell-head reveal" style={{ marginBottom: '1rem' }}>
            <AdminSectionNav sections={adminSections} current={adminSection} onChange={setAdminSection} />
            {activeAdminSection ? (
              <div className="admin-section-status">
                <div className="admin-section-status-copy">
                  <strong>{activeAdminSection.label}</strong>
                  {activeAdminSection.hint ? <span>{activeAdminSection.hint}</span> : null}
                </div>
                {activeAdminSection.badge ? (
                  <StatusBadge tone={activeAdminSection.badgeTone || 'ok'}>
                    {activeAdminSection.badge}
                  </StatusBadge>
                ) : null}
              </div>
            ) : null}
          </section>
        </>
      )}

      {!canManagePlatform ? (
        <SectionCard title={t('admin.requiredTitle')}>
          <EmptyState title={t('admin.requiredTitle')} message={t('admin.requiredMessage')} />
        </SectionCard>
      ) : (
        <div className="admin-grid">
          {adminSection === 'resources' && (
          <div className="panel reveal access-scope-panel">
            <div className="panel-header">
              <div>
                <h3>{editingResourceId ? t('admin.editResource') : t('admin.newResource')}</h3>
              </div>
            </div>
            <form className="resource-form" onSubmit={onSubmitResource}>
              <div className="full resource-section">
                <div className="resource-section-header">
                  <div>
                    <h4>Identity</h4>
                  </div>
                </div>
                <div className="section-grid">
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
                    Description
                    <input
                      name="description"
                      value={resourceForm.description}
                      onChange={onResourceFieldChange}
                      placeholder="Short usage note"
                    />
                  </label>
                  <label>
                    Tags
                    <input
                      name="tagsCsv"
                      value={resourceForm.tagsCsv}
                      onChange={onResourceFieldChange}
                      placeholder="prod, linux, db"
                    />
                  </label>
                  <label className="full">
                    Image URL
                    <input
                      name="imageUrl"
                      value={resourceForm.imageUrl}
                      onChange={onResourceFieldChange}
                      placeholder="https://..."
                      disabled={!!resourceForm.imageData}
                    />
                  </label>
                  <label className="full">
                    Visual upload
                    <input
                      type="file"
                      accept="image/*"
                      onChange={e => {
                        const file = e.target.files[0];
                        if (!file) return;
                        const reader = new window.FileReader();
                        reader.onload = (ev) => {
                          setResourceForm(f => ({ ...f, imageData: ev.target.result, imageUrl: '' }));
                        };
                        reader.readAsDataURL(file);
                      }}
                    />
                    {resourceForm.imageData && (
                      <div className="resource-image-preview">
                        <img src={resourceForm.imageData} alt="aperçu" />
                        <button type="button" className="ghost" onClick={() => setResourceForm(f => ({ ...f, imageData: '' }))}>
                          Remove
                        </button>
                      </div>
                    )}
                  </label>
                </div>
              </div>

              <div className="full resource-section">
                <div className="resource-section-header">
                  <div>
                    <h4>Connectivity</h4>
                  </div>
                </div>
                <div className="section-grid">
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
                  {(resourceForm.protocol === 'agent' || resourceForm.protocol === 'rdp') && (
                    <label>
                      Tunnel ticket limit / min
                      <input
                        name="tunnelTicketRateLimitMaxAttempts"
                        type="number"
                        min="0"
                        step="1"
                        value={resourceForm.tunnelTicketRateLimitMaxAttempts}
                        onChange={onResourceFieldChange}
                        placeholder="0 = unlimited"
                      />
                      <small className="muted">0 = unlimited. Applied per user and per resource.</small>
                    </label>
                  )}
                  {(resourceForm.protocol === 'http' || resourceForm.protocol === 'https') && (
                    <>
                      <label>
                        HTTP Username (optional)
                        <input
                          name="httpUsername"
                          value={resourceForm.httpUsername}
                          onChange={onResourceFieldChange}
                          placeholder="admin"
                          autoComplete="off"
                        />
                      </label>
                      <label>
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
                      <label>
                        Credential flow
                        <select
                          name="credentialSource"
                          value={resourceForm.credentialSource}
                          onChange={onResourceFieldChange}
                        >
                          <option value="vaulted">vaulted lease</option>
                          <option value="brokered">brokered (secret stays server-side)</option>
                          <option value="ephemeral_account">ephemeral account (brokered fallback)</option>
                        </select>
                      </label>
                      <label>
                        SSH Username (vault)
                        <input
                          name="sshUsername"
                          value={resourceForm.sshUsername}
                          onChange={onResourceFieldChange}
                          placeholder="root"
                          autoComplete="off"
                        />
                      </label>
                      <label>
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
                </div>
              </div>

              <div className="full policy-editor">
                <div className="policy-editor-header">
                  <div>
                    <h4>Access Policy</h4>
                  </div>
                  <span className={`pill ${normalizeRiskLevel(resourceForm.riskLevel) === 'critical' ? 'error' : normalizeRiskLevel(resourceForm.riskLevel) === 'high' ? 'warning' : 'ok'}`}>
                    {normalizeRiskLevel(resourceForm.riskLevel)}
                  </span>
                </div>
                <div className="policy-grid">
                  <label className={`policy-option ${resourceForm.requireAccessJustification ? 'selected' : ''}`}>
                    <input
                      name="requireAccessJustification"
                      type="checkbox"
                      checked={!!resourceForm.requireAccessJustification}
                      onChange={onResourceFieldChange}
                    />
                    <span className="policy-option-indicator" aria-hidden="true" />
                    <div className="policy-option-copy">
                      <strong>Justification</strong>
                      <span>Prompt for access reason before connect.</span>
                      <em>{resourceForm.requireAccessJustification ? 'Enabled' : 'Optional'}</em>
                    </div>
                  </label>
                  <label className={`policy-option ${resourceForm.requireDualApproval ? 'selected' : ''}`}>
                    <input
                      name="requireDualApproval"
                      type="checkbox"
                      checked={!!resourceForm.requireDualApproval}
                      onChange={onResourceFieldChange}
                    />
                    <span className="policy-option-indicator" aria-hidden="true" />
                    <div className="policy-option-copy">
                      <strong>Dual approval</strong>
                      <span>Require review before session start.</span>
                      <em>{resourceForm.requireDualApproval ? 'Required' : 'Disabled'}</em>
                    </div>
                  </label>
                  <label className={`policy-option ${resourceForm.enableCommandGuard ? 'selected' : ''}`}>
                    <input
                      name="enableCommandGuard"
                      type="checkbox"
                      checked={!!resourceForm.enableCommandGuard}
                      onChange={onResourceFieldChange}
                    />
                    <span className="policy-option-indicator" aria-hidden="true" />
                    <div className="policy-option-copy">
                      <strong>SSH command guard</strong>
                      <span>Block dangerous commands server-side.</span>
                      <em>{resourceForm.enableCommandGuard ? 'Protected' : 'Not enforced'}</em>
                    </div>
                  </label>
                  <label className={`policy-option ${resourceForm.adaptiveAccessPolicy ? 'selected' : ''}`}>
                    <input
                      name="adaptiveAccessPolicy"
                      type="checkbox"
                      checked={!!resourceForm.adaptiveAccessPolicy}
                      onChange={onResourceFieldChange}
                    />
                    <span className="policy-option-indicator" aria-hidden="true" />
                    <div className="policy-option-copy">
                      <strong>Adaptive controls</strong>
                      <span>Raise requirements automatically based on risk.</span>
                      <em>{resourceForm.adaptiveAccessPolicy ? 'Dynamic' : 'Static'}</em>
                    </div>
                  </label>
                </div>
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
                <div className="policy-preview">
                  {describeResourcePolicy(resourceForm, t).map((item) => (
                    <span className="policy-chip" key={`preview-${item}`}>{item}</span>
                  ))}
                </div>
              </div>

              <div className="full resource-section routing-section">
                <div className="resource-section-header">
                  <div>
                    <h4>Routing</h4>
                  </div>
                </div>
                <div className="routing-summary">
                  <article>
                    <strong>Direct</strong>
                    <span>Backend to target.</span>
                  </article>
                  <article>
                    <strong>Relay</strong>
                    <span>Through assigned relay.</span>
                  </article>
                  <article>
                    <strong>Agent</strong>
                    <span>Local tunnel path.</span>
                  </article>
                </div>
              </div>

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
                        tunnelTicketRateLimitMaxAttempts: '0',
                        description: '',
                        imageUrl: '',
                        imageData: '',
                        tagsCsv: '',
                        credentialSource: 'vaulted',
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
                    {t('common.cancel')}
                  </button>
                )}
              </div>
            </form>
            {resourceError && <p className="error">{resourceError}</p>}
          </div>
          )}

          {adminSection === 'resources' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{t('admin.resources')}</h3>
                <p>{t('admin.configuredTiles', { count: resources.length })}</p>
              </div>
              {loadingResources && <span className="pill loading">{t('common.loading')}</span>}
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
                      {resource.tagsCsv && (
                        <p className="muted">Tags: {resource.tagsCsv}</p>
                      )}
                      {resource.protocol === 'ssh' && (
                        <p className="muted">Credential flow: {resource.credentialSource || 'vaulted'}</p>
                      )}
                      <div className="policy-chip-row">
                        {describeResourcePolicy(resource, t).map((item) => (
                          <span className="policy-chip" key={`${resource.id}-${item}`}>{item}</span>
                        ))}
                      </div>
                    </div>
                    <div className="resource-actions">
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onEditResource(resource)}
                      >
                        {t('common.edit')}
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onDeleteResource(resource.id)}
                      >
                        {t('common.delete')}
                      </button>
                    </div>
                  </article>
                ))
              ) : (
                <p className="muted">{t('admin.noResources')}</p>
              )}
            </div>
          </div>
          )}

          {adminSection === 'routing' && (
          <div className="panel reveal relay-panel">
            <div className="panel-header">
              <div>
                <h3>Relay Fabric</h3>
              </div>
              {loadingRelays && <span className="pill loading">{t('common.syncing')}</span>}
            </div>

            <div className="relay-kpi-grid">
              <article className="relay-kpi-card">
                <span>Total relays</span>
                <strong>{relayInventorySummary.total}</strong>
              </article>
              <article className="relay-kpi-card ok">
                <span>Online</span>
                <strong>{relayInventorySummary.online}</strong>
              </article>
              <article className="relay-kpi-card warning">
                <span>Offline</span>
                <strong>{relayInventorySummary.offline}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>Enrollment</span>
                <strong>{relayConfig.enrollmentEnabled ? 'Enabled' : 'Disabled'}</strong>
              </article>
            </div>

            <div className="relay-enroll-panel">
              <div>
                <h4>Relay Bootstrap</h4>
              </div>
              <div className="relay-enroll-token-box">
                <p><strong>Install helper ({resolveAgentInstallGuide().platform})</strong></p>
                <code className="relay-enroll-command">{resolveAgentInstallGuide().command}</code>
              </div>
              <div className="resource-actions">
                <button
                  type="button"
                  className="ghost"
                  onClick={() => setShowRelayManualBootstrap((prev) => !prev)}
                >
                  {showRelayManualBootstrap ? 'Hide advanced bootstrap' : 'Show advanced bootstrap'}
                </button>
              </div>

              {showRelayManualBootstrap && (
                <>
                  <div><h4>Manual</h4></div>
                  <div className="resource-actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={onIssueRelayCertificate}
                      disabled={issuingRelayCertificate}
                    >
                      {issuingRelayCertificate ? 'Generating certificate...' : 'Generate relay certificate'}
                    </button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={onCopyRelayCertificate}
                      disabled={!relayCertificate}
                    >
                      Copy certificate
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      onClick={onIssueRelayEnrollmentToken}
                      disabled={issuingRelayEnrollmentToken || !relayConfig.enrollmentEnabled}
                    >
                      {issuingRelayEnrollmentToken ? 'Generating token...' : 'Generate enrollment token'}
                    </button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={onCopyRelayEnrollmentToken}
                      disabled={!relayEnrollmentToken}
                    >
                      Copy token
                    </button>
                  </div>
                  {relayCertificate && (
                    <div className="relay-enroll-token-box">
                      <p><strong>Certificate ID</strong>: <code>{relayCertificateId || 'n/a'}</code></p>
                      <p><strong>Certificate</strong>: <code>{relayCertificate}</code></p>
                      <p className="muted">Expires at: {relayCertificateExpiresAt || 'n/a'}</p>
                      {relayCertificateCopyStatus && <p className="muted">{relayCertificateCopyStatus}</p>}
                    </div>
                  )}
                  {!relayConfig.enrollmentEnabled && (
                    <p className="muted">Enrollment secret missing on backend.</p>
                  )}
                  {relayEnrollmentToken && (
                    <div className="relay-enroll-token-box">
                      <p><strong>Token</strong>: <code>{relayEnrollmentToken}</code></p>
                      <p className="muted">Expires at: {relayEnrollmentTokenExpiresAt || 'n/a'}</p>
                      <code className="relay-enroll-command">
                        {`curl -X POST https://localhost:8080/api/relays/enroll -H "Content-Type: application/json" -H "X-EndoriumFort-Relay-Enrollment-Token: ${relayEnrollmentToken}" -H "X-EndoriumFort-Relay-Certificate: <relay-certificate>" -d '{"relayId":"relay-edge-01","label":"Edge Relay 01","version":"1.0.0","capabilities":["ssh","rdp","vnc"]}'`}
                      </code>
                      {relayEnrollmentCopyStatus && <p className="muted">{relayEnrollmentCopyStatus}</p>}
                    </div>
                  )}
                </>
              )}
            </div>

            {relayError && <p className="error">{relayError}</p>}

            <div className="resource-list relay-fleet-list">
              {relays.length ? (
                relays.map((relay) => (
                  <article className="resource-row relay-row" key={relay.relayId}>
                    <div>
                      <h4>{relay.label || relay.relayId}</h4>
                      <p className="muted">ID: {relay.relayId}</p>
                      <p className="muted">{relay.sourceIp || 'n/a'} • {relay.version || 'unknown version'}</p>
                      <p className="muted">Managed resources: {Number(relay.managedResourceCount) || 0}</p>
                    </div>
                    <span className={`pill ${String(relay.status).toLowerCase() === 'online' ? 'ok' : 'offline'}`}>
                      {String(relay.status || 'offline').toLowerCase()}
                    </span>
                  </article>
                ))
              ) : (
                <p className="muted">No relay enrolled yet.</p>
              )}
            </div>

            <div className="panel-header" style={{ marginTop: '0.9rem' }}>
              <div>
                <h3>Resource Routing Assignments</h3>
              </div>
              <label className="relay-filter-toggle">
                <input
                  type="checkbox"
                  checked={relayAssignOnlineOnly}
                  onChange={(event) => setRelayAssignOnlineOnly(event.target.checked)}
                />
                Online relays only
              </label>
            </div>
            <div className="resource-list relay-assignment-list">
              {resources.length ? (
                resources.map((resource) => {
                  const selected = relayBindings[resource.id] || '';
                  const busy = relayAssignBusyResourceId === resource.id;
                  const relayOptions = relayAssignOnlineOnly
                    ? relays.filter((relay) => isRelayOnline(relay) || relay.relayId === selected)
                    : relays;
                  return (
                    <article className="resource-row relay-assign-row" key={`assign-${resource.id}`}>
                      <div>
                        <h4>{resource.name}</h4>
                        <p className="muted">{resource.protocol} {resource.target}:{resource.port}</p>
                      </div>
                      <div className="resource-actions">
                        <select
                          value={selected}
                          disabled={busy || loadingRelays}
                          onChange={(event) => onAssignRelay(resource.id, event.target.value)}
                        >
                          <option value="">direct (no relay)</option>
                          {relayOptions.map((relay) => (
                            <option key={`relay-opt-${resource.id}-${relay.relayId}`} value={relay.relayId}>
                              {relay.label || relay.relayId} ({String(relay.status || 'offline').toLowerCase()})
                            </option>
                          ))}
                        </select>
                      </div>
                    </article>
                  );
                })
              ) : (
                <p className="muted">{t('admin.createResourcesBeforeAssigning')}</p>
              )}
            </div>
          </div>
          )}

          {adminSection === 'routing' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Access Requests</h3>
              </div>
              {loadingAccessRequests && <span className="pill loading">{t('common.loading')}</span>}
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
                          {t('admin.approve')}
                        </button>
                        <button
                          type="button"
                          className="ghost"
                          onClick={() => onDenyAccessRequest(request.id)}
                        >
                          {t('admin.deny')}
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
          )}

          {adminSection === 'users' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{editingUserId ? t('admin.editUser') : t('admin.newUser')}</h3>
              </div>
              {loadingUsers && <span className="pill loading">{t('common.loading')}</span>}
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
                  placeholder={editingUserId ? t('auth.newPassword') : t('auth.password')}
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
              <label className="checkbox-row">
                <input
                  name="forcePasswordRotation"
                  type="checkbox"
                  checked={!!userForm.forcePasswordRotation}
                  onChange={onUserFieldChange}
                />
                <span>Require password rotation on next sign-in</span>
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
                        role: 'operator',
                        forcePasswordRotation: false
                      });
                    }}
                  >
                    {t('common.cancel')}
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
                      <p className="muted">{t('admin.roleLabel', { role: roleLabel(user.role, t) })}</p>
                      {user.bootstrapPasswordChangeRequired && (
                        <p className="muted">Password rotation required at next sign-in.</p>
                      )}
                      {user.role === 'admin' && (
                        <p className="muted">
                          MFA {(user.totpEnabled || user.webauthnEnabled) ? 'enabled' : 'required before platform use'}.
                        </p>
                      )}
                    </div>
                    <div className="resource-actions">
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onEditUser(user)}
                      >
                        {t('common.edit')}
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => onLoadUserPermissions(user)}
                      >
                        Access Scope
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onDeleteUser(user.id)}
                      >
                        {t('common.delete')}
                      </button>
                    </div>
                  </article>
                ))
              ) : (
                <p className="muted">{t('admin.noUsers')}</p>
              )}
            </div>
          </div>
          )}

          {adminSection === 'users' && (
          <div className="panel reveal access-scope-panel">
            <div className="panel-header">
              <div>
                <h3>Access Scope</h3>
              </div>
              {selectedUserForAccessScope && (
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    setSelectedUserForAccessScope(null);
                    setUserResourceScope([]);
                    setUserAccessProfiles([]);
                    setAccessScopeError('');
                  }}
                >
                  {t('common.close')}
                </button>
              )}
            </div>

            {!selectedUserForAccessScope ? (
              <p className="muted">No user selected yet.</p>
            ) : (
              <>
                {loadingAccessScope && <p>{t('admin.loadingAccessScope')}</p>}
                {accessScopeError && <p className="error">{accessScopeError}</p>}
                <div className="panel-header" style={{ marginTop: '0.5rem' }}>
                  <div>
                    <h3>Resource Scope</h3>
                  </div>
                </div>
                <div className="resource-list permissions-resources-list">
                  {resources.length ? (
                    resources.map((resource) => (
                      <article className="resource-row compact-perm-row" key={resource.id}>
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
                              checked={userResourceScope.includes(resource.id)}
                              onChange={() => onToggleResourcePermission(resource.id)}
                              style={{ cursor: 'pointer' }}
                            />
                            <div>
                              <h4>{resource.name}</h4>
                              <p className="muted">
                                {resource.protocol} {resource.target}:{resource.port}
                              </p>
                            </div>
                          </div>
                        </div>
                      </article>
                    ))
                  ) : (
                    <p className="muted">{t('admin.noResourcesYet')}</p>
                  )}
                </div>

                <div className="panel-header" style={{ marginTop: '1rem' }}>
                  <div>
                    <h3>Access Profiles</h3>
                  </div>
                </div>
                <div className="resource-list permissions-resources-list">
                  {accessProfiles.length ? (
                    accessProfiles.map((profile) => (
                      <article className="resource-row compact-perm-row" key={`profile-${profile.id}`}>
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
                              checked={userAccessProfiles.includes(profile.id)}
                              onChange={() => onToggleAccessProfile(profile.id)}
                              style={{ cursor: 'pointer' }}
                            />
                            <div>
                              <h4>{profile.name}</h4>
                              <p className="muted">
                                Policy #{profile.policyId || 0} • {profile.resourceTagsCsv || profile.resourceIdsCsv || 'all assigned resources'}
                              </p>
                            </div>
                          </div>
                        </div>
                      </article>
                    ))
                  ) : (
                    <p className="muted">No access profiles yet.</p>
                  )}
                </div>

                <div className="panel-header" style={{ marginTop: '1rem' }}>
                  <div>
                    <h3>Role Policy</h3>
                  </div>
                </div>
                <div className="resource-list permissions-grid">
                  {(roleBlueprints.find((role) => role.id === normalizeRole(selectedUserForAccessScope.role))?.permissions || [])
                    .map((permission) => (
                      <article className="resource-row compact-perm-row" key={permission}>
                        <div>
                          <h4>{permission}</h4>
                          <p className="muted">
                            {t('admin.grantedByRole', { role: roleLabel(selectedUserForAccessScope.role, t) })}
                          </p>
                        </div>
                      </article>
                    ))}
                </div>
              </>
            )}
          </div>
          )}

          {adminSection === 'jit' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{editingAccessPolicyId ? 'Edit access policy' : 'New access policy'}</h3>
              </div>
              {loadingAccessPolicies && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitAccessPolicy}>
              <label>
                Name
                <input name="name" value={accessPolicyForm.name} onChange={onAccessPolicyFieldChange} />
              </label>
              <label>
                Identity
                <input name="identityPattern" value={accessPolicyForm.identityPattern} onChange={onAccessPolicyFieldChange} placeholder="user or *" />
              </label>
              <label>
                Role
                <input name="role" value={accessPolicyForm.role} onChange={onAccessPolicyFieldChange} placeholder="operator/admin" />
              </label>
              <label>
                Group
                <input name="groupName" value={accessPolicyForm.groupName} onChange={onAccessPolicyFieldChange} placeholder="optional local group alias" />
              </label>
              <label className="full">
                Resource tags
                <input name="resourceTagsCsv" value={accessPolicyForm.resourceTagsCsv} onChange={onAccessPolicyFieldChange} placeholder="prod, db, linux" />
              </label>
              <label className="full">
                Description
                <input name="description" value={accessPolicyForm.description} onChange={onAccessPolicyFieldChange} />
              </label>
              <label>
                Risk
                <select name="riskLevel" value={accessPolicyForm.riskLevel} onChange={onAccessPolicyFieldChange}>
                  <option value="any">any</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
              <label>
                Approval mode
                <select name="approvalMode" value={accessPolicyForm.approvalMode} onChange={onAccessPolicyFieldChange}>
                  <option value="inherit">inherit</option>
                  <option value="none">none</option>
                  <option value="required">required</option>
                </select>
              </label>
              <label>
                MFA
                <select name="mfaRequirement" value={accessPolicyForm.mfaRequirement} onChange={onAccessPolicyFieldChange}>
                  <option value="any">any</option>
                  <option value="required">required</option>
                  <option value="totp">totp</option>
                  <option value="webauthn">webauthn</option>
                </select>
              </label>
              <label>
                Routing
                <select name="routingConstraint" value={accessPolicyForm.routingConstraint} onChange={onAccessPolicyFieldChange}>
                  <option value="any">any</option>
                  <option value="direct">direct</option>
                  <option value="relay">relay</option>
                </select>
              </label>
              <label>
                Time window (UTC)
                <input name="timeWindow" value={accessPolicyForm.timeWindow} onChange={onAccessPolicyFieldChange} placeholder="any or 08:00-18:00" />
              </label>
              <label>
                Max duration (s)
                <input name="maxDurationSeconds" type="number" min="300" step="60" value={accessPolicyForm.maxDurationSeconds} onChange={onAccessPolicyFieldChange} />
              </label>
              <label className="checkbox-row">
                <input name="ticketRequired" type="checkbox" checked={!!accessPolicyForm.ticketRequired} onChange={onAccessPolicyFieldChange} />
                <span>Ticket required</span>
              </label>
              <label className="checkbox-row">
                <input name="requireJustification" type="checkbox" checked={!!accessPolicyForm.requireJustification} onChange={onAccessPolicyFieldChange} />
                <span>Justification required</span>
              </label>
              <label className="checkbox-row">
                <input name="enabled" type="checkbox" checked={!!accessPolicyForm.enabled} onChange={onAccessPolicyFieldChange} />
                <span>Enabled</span>
              </label>
              <div className="resource-actions">
                <button type="submit">{editingAccessPolicyId ? 'Update' : 'Create'} policy</button>
                {editingAccessPolicyId && (
                  <button type="button" className="ghost" onClick={resetAccessPolicyForm}>
                    {t('common.cancel')}
                  </button>
                )}
              </div>
            </form>
            {accessPolicyError && <p className="error">{accessPolicyError}</p>}
            <div className="resource-list">
              {accessPolicies.length ? accessPolicies.map((policy) => (
                <article className="resource-row" key={`policy-${policy.id}`}>
                  <div>
                    <h4>{policy.name}</h4>
                    <p className="muted">
                      {policy.resourceTagsCsv || 'all resources'} • {policy.approvalMode} • {policy.mfaRequirement} • TTL {policy.maxDurationSeconds}s
                    </p>
                  </div>
                  <div className="resource-actions">
                    <button type="button" className="secondary" onClick={() => onEditAccessPolicy(policy)}>Edit</button>
                    <button type="button" className="ghost" onClick={() => onDeleteAccessPolicy(policy.id)}>Delete</button>
                  </div>
                </article>
              )) : <p className="muted">No access policies yet.</p>}
            </div>
          </div>
          )}

          {adminSection === 'jit' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>{editingAccessProfileId ? 'Edit access profile' : 'New access profile'}</h3>
              </div>
              {loadingAccessProfiles && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitAccessProfile}>
              <label>
                Name
                <input name="name" value={accessProfileForm.name} onChange={onAccessProfileFieldChange} />
              </label>
              <label>
                Policy
                <select name="policyId" value={accessProfileForm.policyId} onChange={onAccessProfileFieldChange}>
                  <option value="0">none</option>
                  {accessPolicies.map((policy) => (
                    <option key={`profile-policy-${policy.id}`} value={policy.id}>{policy.name}</option>
                  ))}
                </select>
              </label>
              <label className="full">
                Resource IDs
                <input name="resourceIdsCsv" value={accessProfileForm.resourceIdsCsv} onChange={onAccessProfileFieldChange} placeholder="1,2,3" />
              </label>
              <label className="full">
                Resource tags
                <input name="resourceTagsCsv" value={accessProfileForm.resourceTagsCsv} onChange={onAccessProfileFieldChange} placeholder="prod,windows" />
              </label>
              <label className="full">
                Description
                <input name="description" value={accessProfileForm.description} onChange={onAccessProfileFieldChange} />
              </label>
              <div className="resource-actions">
                <button type="submit">{editingAccessProfileId ? 'Update' : 'Create'} profile</button>
                {editingAccessProfileId && (
                  <button type="button" className="ghost" onClick={resetAccessProfileForm}>
                    {t('common.cancel')}
                  </button>
                )}
              </div>
            </form>
            {accessProfileError && <p className="error">{accessProfileError}</p>}
            <div className="resource-list">
              {accessProfiles.length ? accessProfiles.map((profile) => (
                <article className="resource-row" key={`profile-row-${profile.id}`}>
                  <div>
                    <h4>{profile.name}</h4>
                    <p className="muted">
                      Policy #{profile.policyId || 0} • {profile.resourceTagsCsv || profile.resourceIdsCsv || 'all assigned resources'}
                    </p>
                  </div>
                  <div className="resource-actions">
                    <button type="button" className="secondary" onClick={() => onEditAccessProfile(profile)}>Edit</button>
                    <button type="button" className="ghost" onClick={() => onDeleteAccessProfile(profile.id)}>Delete</button>
                  </div>
                </article>
              )) : <p className="muted">No access profiles yet.</p>}
            </div>
          </div>
          )}

          {adminSection === 'jit' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Access Grants</h3>
                <p>Issued JIT grants and their current TTL/status.</p>
              </div>
              {loadingAccessGrants && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            {accessGrantError && <p className="error">{accessGrantError}</p>}
            <div className="resource-list">
              {accessGrants.length ? accessGrants.map((grant) => (
                <article className="resource-row" key={`grant-${grant.id}`}>
                  <div>
                    <h4>Grant #{grant.id}</h4>
                    <p className="muted">
                      {grant.subject} • resource #{grant.resourceId} • {grant.status}
                    </p>
                    <p className="muted">
                      Expires {grant.expiresAt} • {grant.credentialSource} • {grant.routingConstraint}
                    </p>
                  </div>
                </article>
              )) : <p className="muted">No JIT grant issued yet.</p>}
            </div>
          </div>
          )}

          {adminSection === 'enterprise' && (
          <div className="panel reveal relay-panel">
            <div className="panel-header">
              <div>
                <h3>Enterprise IAM</h3>
                <p>
                  {locale === 'fr'
                    ? 'Fédération d’identité, provisioning SCIM et validations d’intégrations.'
                    : 'Identity federation, SCIM provisioning and integration validation workspace.'}
                </p>
              </div>
              {enterpriseLoading && <span className="pill loading">{t('common.syncing')}</span>}
            </div>
            {enterpriseError && <p className="error">{enterpriseError}</p>}

            <div className="relay-kpi-grid">
              <article className="relay-kpi-card">
                <span>Directory providers</span>
                <strong>{enterpriseDirectoryProviders.length}</strong>
              </article>
              <article className={`relay-kpi-card ${enterpriseLdapConfig?.enabled ? 'ok' : ''}`}>
                <span>LDAP/AD</span>
                <strong>{enterpriseLdapConfig?.enabled ? 'enabled' : 'disabled'}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>SSO providers</span>
                <strong>{enterpriseSsoProviders.length}</strong>
              </article>
              <article className="relay-kpi-card ok">
                <span>SCIM PATCH</span>
                <strong>{enterpriseScimConfig?.patch?.supported ? 'enabled' : 'disabled'}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>ITSM providers</span>
                <strong>{enterpriseItsmProviders.length}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>SIEM channels</span>
                <strong>{enterpriseSiemChannels.length}</strong>
              </article>
              <article className={`relay-kpi-card ${enterpriseClusterStatus?.enabled ? 'ok' : 'warning'}`}>
                <span>Cluster mode</span>
                <strong>{enterpriseClusterStatus?.enabled ? 'enabled' : 'disabled'}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>Cluster nodes</span>
                <strong>{Number(enterpriseClusterStatus?.summary?.nodesTotal) || 1}</strong>
              </article>
            </div>

            <form className="resource-form" onSubmit={(event) => {
              event.preventDefault();
              onStartEnterpriseSso();
            }}>
              <label>
                SSO provider
                <select
                  value={enterpriseSsoProvider}
                  onChange={(event) => setEnterpriseSsoProvider(event.target.value)}
                >
                  {enterpriseSsoProviders.length ? enterpriseSsoProviders.map((provider) => (
                    <option key={`sso-provider-${provider.id}`} value={provider.id}>
                      {provider.name || provider.id} ({provider.protocol || 'oidc'})
                    </option>
                  )) : (
                    <option value="">n/a</option>
                  )}
                </select>
              </label>
              <div className="resource-actions">
                <button type="submit" className="secondary" disabled={!enterpriseSsoProviders.length}>
                  {locale === 'fr' ? 'Tester la connexion OIDC' : 'Test OIDC sign-in'}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    refreshEnterpriseWorkspace().catch(() => {});
                  }}
                  disabled={enterpriseLoading || enterpriseScimLoading}
                >
                  {locale === 'fr' ? 'Rafraichir les fondations IAM' : 'Refresh IAM foundations'}
                </button>
              </div>
            </form>

            <div className="relay-enroll-token-box">
              <p>
                <strong>Default provider</strong>: {enterpriseSsoConfig?.defaultProvider || 'n/a'}
              </p>
              <p>
                <strong>LDAP host</strong>: {enterpriseLdapConfig?.host || 'n/a'}
              </p>
              <p>
                <strong>LDAP base DN</strong>: {enterpriseLdapConfig?.baseDn || 'n/a'}
              </p>
              <p>
                <strong>LDAP auth mode</strong>: {enterpriseLdapConfig?.authMode || 'n/a'}
              </p>
              <p>
                <strong>LDAP default role</strong>: {enterpriseLdapConfig?.defaultRole || 'operator'}
              </p>
              <p>
                <strong>LDAP role mapping</strong>: {enterpriseLdapConfig?.roleMappingEnabled
                  ? `${locale === 'fr' ? 'active' : 'enabled'} (${enterpriseLdapConfig?.roleMapEntries || 0} ${locale === 'fr' ? 'regles' : 'rules'})`
                  : (locale === 'fr' ? 'desactive' : 'disabled')}
              </p>
              <p>
                <strong>Single tenant</strong>: {enterpriseSsoConfig?.singleTenant ? 'yes' : 'no'}
              </p>
              <p>
                <strong>OIDC start</strong>: {enterpriseSsoConfig?.oidcStartPath || '/api/auth/sso/oidc/start'}
              </p>
              <p>
                <strong>OIDC callback</strong>: {enterpriseSsoConfig?.oidcCallbackPath || '/api/auth/sso/oidc/callback'}
              </p>
              <p className="muted">
                {locale === 'fr'
                  ? 'Endpoints OIDC en HTTPS pris en charge avec validation de certificat système.'
                  : 'OIDC endpoints support HTTPS with system trust-store certificate validation.'}
              </p>
            </div>

            <div className="panel-header" style={{ marginTop: '0.2rem' }}>
              <div>
                <h3>Cluster / HA Control Plane</h3>
                <p>
                  {locale === 'fr'
                    ? 'Etat local, heartbeat inter-noeuds et inventaire des pairs.'
                    : 'Local node posture, inter-node heartbeat health, and peer inventory.'}
                </p>
              </div>
            </div>

            <div className="relay-enroll-token-box">
              <p>
                <strong>Node ID</strong>: {enterpriseClusterConfig?.nodeId || enterpriseClusterStatus?.localNode?.nodeId || 'node-local'}
              </p>
              <p>
                <strong>Node label</strong>: {enterpriseClusterConfig?.nodeLabel || enterpriseClusterStatus?.localNode?.label || 'Primary Node'}
              </p>
              <p>
                <strong>Role</strong>: {enterpriseClusterConfig?.role || enterpriseClusterStatus?.localNode?.role || 'standalone'}
              </p>
              <p>
                <strong>Advertise address</strong>: {enterpriseClusterConfig?.advertiseAddr || enterpriseClusterStatus?.localNode?.endpoint || 'n/a'}
              </p>
              <p>
                <strong>Peer auth</strong>: {enterpriseClusterConfig?.peerAuthRequired ? 'required' : 'disabled'}
              </p>
              <p>
                <strong>Heartbeat stale threshold</strong>: {enterpriseClusterConfig?.heartbeatStaleSeconds || enterpriseClusterStatus?.heartbeatStaleSeconds || 45}s
              </p>
              <p>
                <strong>Summary</strong>: {(Number(enterpriseClusterStatus?.summary?.nodesOnline) || 1)} online / {(Number(enterpriseClusterStatus?.summary?.nodesOffline) || 0)} offline
              </p>
            </div>

            {enterpriseClusterPeerMessage && <p className="muted">{enterpriseClusterPeerMessage}</p>}

            <div className="resource-list relay-fleet-list">
              {Array.isArray(enterpriseClusterStatus?.peers) && enterpriseClusterStatus.peers.length ? enterpriseClusterStatus.peers.map((peer) => {
                const peerStatus = String(peer?.status || '').toLowerCase() === 'online' ? 'online' : 'offline';
                return (
                  <article className="resource-row relay-row" key={`cluster-peer-${peer.nodeId}`}>
                    <div>
                      <h4>{peer.label || peer.nodeId}</h4>
                      <p className="muted">
                        {peer.nodeId} • {peer.role || 'follower'} • {peer.endpoint || peer.sourceIp || 'n/a'}
                      </p>
                      <p className="muted">
                        version {peer.version || 'n/a'} • relays {Number(peer.managedRelays) || 0} • sessions {Number(peer.managedSessions) || 0}
                      </p>
                    </div>
                    <div className="resource-actions">
                      <span className={`pill ${peerStatus === 'online' ? 'ok' : 'offline'}`}>{peerStatus}</span>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onRemoveEnterpriseClusterPeer(peer.nodeId)}
                        disabled={enterpriseClusterPeerBusy === peer.nodeId}
                      >
                        {enterpriseClusterPeerBusy === peer.nodeId
                          ? (locale === 'fr' ? 'Suppression...' : 'Removing...')
                          : (locale === 'fr' ? 'Retirer' : 'Remove')}
                      </button>
                    </div>
                  </article>
                );
              }) : (
                <p className="muted">
                  {locale === 'fr' ? 'Aucun pair cluster recu pour le moment.' : 'No cluster peer heartbeat received yet.'}
                </p>
              )}
            </div>
          </div>
          )}

          {adminSection === 'enterprise' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Directory Integrations</h3>
                <p>
                  {locale === 'fr'
                    ? 'Inventaire des annuaires et test de bind LDAP/Active Directory.'
                    : 'Directory inventory and LDAP/Active Directory bind-test workspace.'}
                </p>
              </div>
            </div>

            <div className="resource-list">
              {enterpriseDirectoryProviders.length ? enterpriseDirectoryProviders.map((provider) => (
                <article className="resource-row" key={`directory-provider-${provider.id}`}>
                  <div>
                    <h4>{provider.name || provider.id}</h4>
                    <p className="muted">
                      id: {provider.id || 'n/a'} • jitProvisioning: {provider.jitProvisioning ? 'yes' : 'no'}
                    </p>
                  </div>
                  <span className={`pill ${provider.enabled ? 'ok' : 'offline'}`}>
                    {provider.enabled ? 'enabled' : 'disabled'}
                  </span>
                </article>
              )) : (
                <p className="muted">
                  {locale === 'fr' ? 'Aucun provider annuaire déclaré.' : 'No directory provider available.'}
                </p>
              )}
            </div>

            <div className="panel-header" style={{ marginTop: '0.8rem' }}>
              <div>
                <h3>LDAP bind test</h3>
              </div>
              {enterpriseLdapTesting && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitEnterpriseLdapTest}>
              <label>
                username
                <input
                  value={enterpriseLdapTestUsername}
                  onChange={(event) => setEnterpriseLdapTestUsername(event.target.value)}
                  placeholder={enterpriseLdapConfig?.userTemplate || 'uid={username},ou=People,dc=example,dc=org'}
                />
              </label>
              <label>
                password
                <input
                  type="password"
                  value={enterpriseLdapTestPassword}
                  onChange={(event) => setEnterpriseLdapTestPassword(event.target.value)}
                  autoComplete="current-password"
                  placeholder="••••••••"
                />
              </label>
              <div className="resource-actions">
                <button
                  type="submit"
                  className="secondary"
                  disabled={enterpriseLdapTesting || !enterpriseLdapConfig?.enabled}
                >
                  {enterpriseLdapTesting
                    ? (locale === 'fr' ? 'Test en cours...' : 'Testing...')
                    : (locale === 'fr' ? 'Tester le bind LDAP' : 'Run LDAP bind test')}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => {
                    setEnterpriseLdapTestUsername('');
                    setEnterpriseLdapTestPassword('');
                    setEnterpriseLdapTestResult(null);
                  }}
                >
                  {locale === 'fr' ? 'Effacer' : 'Clear'}
                </button>
              </div>
            </form>
            {enterpriseLdapTestResult && (
              <div className="relay-enroll-token-box">
                <p>
                  <strong>LDAP bind result</strong>
                </p>
                <code className="relay-enroll-command">{JSON.stringify(enterpriseLdapTestResult, null, 2)}</code>
              </div>
            )}
          </div>
          )}

          {adminSection === 'enterprise' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>SCIM Directory Explorer</h3>
                <p>
                  {locale === 'fr'
                    ? 'Interrogez Users/Groups avec startIndex, count et filter (eq/co/sw).'
                    : 'Query Users/Groups with startIndex, count and filter (eq/co/sw).'}
                </p>
              </div>
              {enterpriseScimLoading && <span className="pill loading">{t('common.loading')}</span>}
            </div>

            <form className="resource-form" onSubmit={onSubmitEnterpriseScimFilter}>
              <label className="full">
                SCIM filter
                <input
                  value={enterpriseScimFilter}
                  onChange={(event) => setEnterpriseScimFilter(event.target.value)}
                  placeholder={'userName co "admin"'}
                />
              </label>
              <label>
                startIndex
                <input
                  type="number"
                  min="1"
                  value={enterpriseScimStartIndex}
                  onChange={(event) => setEnterpriseScimStartIndex(event.target.value)}
                />
              </label>
              <label>
                count
                <input
                  type="number"
                  min="0"
                  max="200"
                  value={enterpriseScimCount}
                  onChange={(event) => setEnterpriseScimCount(event.target.value)}
                />
              </label>
              <div className="resource-actions">
                <button type="submit" className="secondary">
                  {locale === 'fr' ? 'Rechercher SCIM' : 'Query SCIM'}
                </button>
              </div>
            </form>

            {enterpriseScimError && <p className="error">{enterpriseScimError}</p>}

            <div className="relay-kpi-grid">
              <article className="relay-kpi-card">
                <span>Users total</span>
                <strong>{enterpriseScimMeta.users.totalResults}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>Users page</span>
                <strong>{enterpriseScimMeta.users.itemsPerPage}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>Groups total</span>
                <strong>{enterpriseScimMeta.groups.totalResults}</strong>
              </article>
              <article className="relay-kpi-card">
                <span>Groups page</span>
                <strong>{enterpriseScimMeta.groups.itemsPerPage}</strong>
              </article>
            </div>

            <div className="panel-header" style={{ marginTop: '0.9rem' }}>
              <div>
                <h3>SCIM Users</h3>
              </div>
            </div>
            <div className="resource-list">
              {enterpriseScimUsers.length ? enterpriseScimUsers.map((user) => {
                const scimRole = Array.isArray(user?.roles) && user.roles.length
                  ? String(user.roles[0]?.value || user.roles[0]?.display || '')
                  : '';
                return (
                  <article className="resource-row" key={`scim-user-${user.id || user.userName}`}>
                    <div>
                      <h4>{user.userName || user.id}</h4>
                      <p className="muted">id: {user.id || 'n/a'} • role: {scimRole || 'n/a'}</p>
                    </div>
                    <span className={`pill ${user.active ? 'ok' : 'offline'}`}>{user.active ? 'active' : 'inactive'}</span>
                  </article>
                );
              }) : (
                <p className="muted">
                  {locale === 'fr' ? 'Aucun utilisateur SCIM trouvé pour ce filtre.' : 'No SCIM user matched this filter.'}
                </p>
              )}
            </div>

            <div className="panel-header" style={{ marginTop: '0.9rem' }}>
              <div>
                <h3>SCIM Groups</h3>
              </div>
            </div>
            <div className="resource-list">
              {enterpriseScimGroups.length ? enterpriseScimGroups.map((group) => (
                <article className="resource-row" key={`scim-group-${group.id || group.displayName}`}>
                  <div>
                    <h4>{group.displayName || group.id}</h4>
                    <p className="muted">
                      id: {group.id || 'n/a'} • members: {Array.isArray(group.members) ? group.members.length : 0}
                    </p>
                  </div>
                </article>
              )) : (
                <p className="muted">
                  {locale === 'fr' ? 'Aucun groupe SCIM trouvé pour ce filtre.' : 'No SCIM group matched this filter.'}
                </p>
              )}
            </div>

            <div className="panel-header" style={{ marginTop: '0.9rem' }}>
              <div>
                <h3>SCIM PATCH Workspace</h3>
              </div>
              {enterpriseScimPatchLoading && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitEnterpriseScimPatch}>
              <label>
                user id / userName
                <input
                  value={enterpriseScimPatchId}
                  onChange={(event) => setEnterpriseScimPatchId(event.target.value)}
                  placeholder="admin"
                />
              </label>
              <label>
                new userName
                <input
                  value={enterpriseScimPatchUsername}
                  onChange={(event) => setEnterpriseScimPatchUsername(event.target.value)}
                  placeholder={locale === 'fr' ? 'optionnel' : 'optional'}
                />
              </label>
              <label>
                role
                <select
                  value={enterpriseScimPatchRole}
                  onChange={(event) => setEnterpriseScimPatchRole(event.target.value)}
                >
                  <option value="">{locale === 'fr' ? 'inchangé' : 'unchanged'}</option>
                  <option value="operator">operator</option>
                  <option value="admin">admin</option>
                  <option value="auditor">auditor</option>
                </select>
              </label>
              <label>
                active
                <select
                  value={enterpriseScimPatchActive}
                  onChange={(event) => setEnterpriseScimPatchActive(event.target.value)}
                >
                  <option value="unchanged">{locale === 'fr' ? 'inchangé' : 'unchanged'}</option>
                  <option value="active">true</option>
                  <option value="inactive">false</option>
                </select>
              </label>
              <div className="resource-actions">
                <button type="submit" className="secondary" disabled={enterpriseScimPatchLoading}>
                  {enterpriseScimPatchLoading
                    ? (locale === 'fr' ? 'Patch en cours...' : 'Patching...')
                    : 'Apply SCIM patch'}
                </button>
              </div>
            </form>
            {enterpriseScimPatchResult && <p className="muted">{enterpriseScimPatchResult}</p>}
          </div>
          )}

          {adminSection === 'enterprise' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Integration Drills</h3>
                <p>
                  {locale === 'fr'
                    ? 'Validez les chemins ITSM fail-open/fail-closed et le forwarding SIEM.'
                    : 'Validate ITSM fail-open/fail-closed and SIEM forwarding behavior.'}
                </p>
              </div>
            </div>

            <div className="panel-header" style={{ marginTop: '0.4rem' }}>
              <div>
                <h3>ITSM ticket verification</h3>
              </div>
              {enterpriseItsmLoading && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitEnterpriseItsmVerification}>
              <label>
                provider
                <select
                  value={enterpriseItsmProvider}
                  onChange={(event) => setEnterpriseItsmProvider(event.target.value)}
                >
                  {enterpriseItsmProviders.length ? enterpriseItsmProviders.map((provider) => (
                    <option key={`itsm-provider-${provider.id}`} value={provider.id}>
                      {provider.name || provider.id}
                    </option>
                  )) : (
                    <option value="servicenow">servicenow</option>
                  )}
                </select>
              </label>
              <label>
                ticketId
                <input
                  value={enterpriseItsmTicketId}
                  onChange={(event) => setEnterpriseItsmTicketId(event.target.value)}
                  placeholder="INC-2026-0042"
                />
              </label>
              <label>
                failMode
                <select
                  value={enterpriseItsmFailMode}
                  onChange={(event) => setEnterpriseItsmFailMode(event.target.value)}
                >
                  <option value="fail-closed">fail-closed</option>
                  <option value="fail-open">fail-open</option>
                </select>
              </label>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={enterpriseItsmUnavailable}
                  onChange={(event) => setEnterpriseItsmUnavailable(event.target.checked)}
                />
                <span>simulateUnavailable</span>
              </label>
              <div className="resource-actions">
                <button type="submit" className="secondary" disabled={enterpriseItsmLoading}>
                  {enterpriseItsmLoading
                    ? (locale === 'fr' ? 'Vérification...' : 'Verifying...')
                    : (locale === 'fr' ? 'Vérifier le ticket' : 'Verify ticket')}
                </button>
              </div>
            </form>
            {enterpriseItsmResult && (
              <div className="relay-enroll-token-box">
                <p><strong>ITSM result</strong></p>
                <code className="relay-enroll-command">{JSON.stringify(enterpriseItsmResult, null, 2)}</code>
              </div>
            )}

            <div className="panel-header" style={{ marginTop: '0.7rem' }}>
              <div>
                <h3>SIEM event forwarding</h3>
              </div>
              {enterpriseSiemLoading && <span className="pill loading">{t('common.loading')}</span>}
            </div>
            <form className="resource-form" onSubmit={onSubmitEnterpriseSiemDispatch}>
              <label>
                channel
                <select
                  value={enterpriseSiemChannel}
                  onChange={(event) => setEnterpriseSiemChannel(event.target.value)}
                >
                  {enterpriseSiemChannels.length ? enterpriseSiemChannels.map((channel) => (
                    <option key={`siem-channel-${channel.id}`} value={channel.id}>
                      {channel.name || channel.id}
                    </option>
                  )) : (
                    <option value="json_webhook">json_webhook</option>
                  )}
                </select>
              </label>
              <label>
                eventType
                <input
                  value={enterpriseSiemEventType}
                  onChange={(event) => setEnterpriseSiemEventType(event.target.value)}
                  placeholder="security.incident.escalated"
                />
              </label>
              <label>
                deliveryMode
                <select
                  value={enterpriseSiemDeliveryMode}
                  onChange={(event) => setEnterpriseSiemDeliveryMode(event.target.value)}
                >
                  <option value="fail-open">fail-open</option>
                  <option value="fail-closed">fail-closed</option>
                </select>
              </label>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={enterpriseSiemSimulateFailure}
                  onChange={(event) => setEnterpriseSiemSimulateFailure(event.target.checked)}
                />
                <span>simulateFailure</span>
              </label>
              <div className="resource-actions">
                <button type="submit" className="secondary" disabled={enterpriseSiemLoading}>
                  {enterpriseSiemLoading
                    ? (locale === 'fr' ? 'Envoi...' : 'Forwarding...')
                    : (locale === 'fr' ? 'Transmettre l’événement' : 'Forward event')}
                </button>
              </div>
            </form>
            {enterpriseSiemResult && (
              <div className="relay-enroll-token-box">
                <p><strong>SIEM result</strong></p>
                <code className="relay-enroll-command">{JSON.stringify(enterpriseSiemResult, null, 2)}</code>
              </div>
            )}
          </div>
          )}

          {adminSection === 'security' && stats && (
            <SectionCard
              title="Security Posture"
              actions={
                <div className="status-row">
                  <StatusBadge tone={stats.auth?.webauthn?.configured ? 'ok' : 'loading'}>
                    {stats.auth?.webauthn?.configured ? 'WebAuthn ready' : 'WebAuthn needs attention'}
                  </StatusBadge>
                </div>
              }
              className="security-posture-panel"
            >
              <div className="security-posture-grid">
                <article className="security-posture-card">
                  <StatusBadge tone={(stats.users?.adminsWithoutMfa || 0) === 0 ? 'ok' : 'loading'}>
                    {(stats.users?.adminsWithoutMfa || 0) === 0 ? 'Protected' : 'Action needed'}
                  </StatusBadge>
                  <h4>{stats.users?.adminsWithoutMfa || 0}</h4>
                </article>
                <article className="security-posture-card">
                  <StatusBadge tone={(stats.users?.adminsPendingBootstrap || 0) === 0 ? 'ok' : 'active'}>
                    {(stats.users?.adminsPendingBootstrap || 0) === 0 ? 'Cleared' : 'Bootstrap pending'}
                  </StatusBadge>
                  <h4>{stats.users?.adminsPendingBootstrap || 0}</h4>
                </article>
                <article className="security-posture-card">
                  <StatusBadge tone={stats.auth?.webauthn?.rpIdValid ? 'ok' : 'loading'}>
                    {stats.auth?.webauthn?.rpIdValid ? 'RP ID valid' : 'RP ID invalid'}
                  </StatusBadge>
                  <h4>{stats.auth?.webauthn?.rpId || 'n/a'}</h4>
                </article>
                <article className="security-posture-card">
                  <StatusBadge tone={stats.auth?.webauthn?.originValid ? 'ok' : 'loading'}>
                    {stats.auth?.webauthn?.originValid ? 'Origin valid' : 'Origin invalid'}
                  </StatusBadge>
                  <h4>{stats.auth?.webauthn?.origin || 'n/a'}</h4>
                </article>
                <article className="security-posture-card">
                  <StatusBadge tone={stats.relay?.runtime?.enrollmentEnabled ? 'ok' : 'loading'}>
                    {stats.relay?.runtime?.enrollmentEnabled ? 'Relay enrollment on' : 'Relay enrollment off'}
                  </StatusBadge>
                  <h4>{stats.relay?.runtime?.heartbeatStaleSeconds || 0}s</h4>
                </article>
              </div>
            </SectionCard>
          )}

          {/* 2FA Management Panel */}
          {adminSection === 'security' && (
          <div className="panel reveal">
            <div className="panel-header">
              <div>
                <h3>Two-Factor Authentication</h3>
              </div>
              <span className={`pill ${(totpEnabled || webauthnEnabled) ? 'ok' : 'loading'}`}>
                {(totpEnabled || webauthnEnabled) ? 'enabled' : 'disabled'}
              </span>
            </div>
              <div className="mfa-panel-block">
                <div className="mfa-preference-grid">
                  <button
                    type="button"
                    className={`ghost ${preferredMfaMethod === 'any' ? 'selected-pref' : ''}`}
                    onClick={() => onUpdateMfaPreference('any')}
                  >
                    Flexible
                  </button>
                  <button
                    type="button"
                    className={`ghost ${preferredMfaMethod === 'totp' ? 'selected-pref' : ''}`}
                    onClick={() => onUpdateMfaPreference('totp')}
                    disabled={!totpEnabled}
                  >
                    Prefer TOTP
                  </button>
                  <button
                    type="button"
                    className={`ghost ${preferredMfaMethod === 'webauthn' ? 'selected-pref' : ''}`}
                    onClick={() => onUpdateMfaPreference('webauthn')}
                    disabled={!webauthnEnabled}
                  >
                    {t('admin.preferPasskey')}
                  </button>
                </div>
              </div>
              {totpError && <p className="error">{totpError}</p>}
              {!totpEnabled && !totpSetupData && (
                <div className="mfa-panel-block">
                  <button type="button" onClick={onSetup2FA} className="mfa-inline-action">
                    Setup TOTP MFA
                  </button>
                </div>
              )}
              {totpSetupData && (
              <div className="mfa-panel-block">
                {totpQrDataUrl && (
                  <div className="bootstrap-qr-image-card mfa-qr-card">
                    <img src={totpQrDataUrl} alt="Local TOTP QR Code" width={220} height={220} />
                  </div>
                )}
                <div className="mfa-setup-card">
                  <strong>Manual secret</strong>
                  <code className="inline-secret">{totpSetupData.secret}</code>
                  <div className="resource-actions">
                    <button type="button" className="ghost" onClick={() => onCopyTotpValue(totpSetupData.secret, 'Secret')}>
                      Copy secret
                    </button>
                    <button type="button" className="ghost" onClick={() => onCopyTotpValue(totpSetupData.otpauthUri, 'Enrollment URI')}>
                      Copy URI
                    </button>
                  </div>
                </div>
                {totpCopyStatus && <p className="muted">{totpCopyStatus}</p>}
                <label>
                  Enter code from your authenticator or hardware token
                  <input
                    className="mfa-code-input"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpSetupCode}
                    onChange={(e) => setTotpSetupCode(e.target.value)}
                    placeholder="123456"
                  />
                </label>
                <div className="resource-actions mfa-inline-action">
                  <button type="button" onClick={onVerify2FA}>
                    Verify &amp; Enable
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => { setTotpSetupData(null); setTotpSetupCode(''); }}
                  >
                    {t('common.cancel')}
                  </button>
                </div>
              </div>
            )}
            <div className="mfa-panel-block">
              <label>
                {t('admin.passkeyLabel')}
                <input
                  className="mfa-code-input"
                  type="text"
                  value={webauthnLabel}
                  onChange={(e) => setWebauthnLabel(e.target.value)}
                  placeholder="Primary security key"
                />
              </label>
              <div className="resource-actions mfa-inline-action">
                <button
                  type="button"
                  onClick={() => onRegisterPasskey(webauthnLabel)}
                  disabled={webauthnBusy || !isWebAuthnSupported()}
                >
                  {webauthnBusy ? 'Registering...' : 'Register passkey'}
                </button>
              </div>
              {!isWebAuthnSupported() && (
                <p className="mfa-hint">WebAuthn unavailable in this browser.</p>
              )}
              {webauthnCredentials.length > 0 && (
                <div className="mfa-passkey-list">
                  {webauthnCredentials.map((credential) => (
                    <article key={credential.id} className="mfa-passkey-item">
                      <div>
                        <strong>{credential.label || t('admin.passkey')}</strong>
                        <p className="muted">
                          Added {formatRelativeDate(credential.createdAt)}
                          {credential.lastUsedAt ? ` · used ${formatRelativeDate(credential.lastUsedAt)}` : ''}
                        </p>
                      </div>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => onDeletePasskey(credential.id)}
                        disabled={webauthnBusy || (auth.role === 'admin' && !totpEnabled && webauthnCredentials.length <= 1)}
                      >
                        Remove
                      </button>
                    </article>
                  ))}
                </div>
              )}
              {auth.role === 'admin' && !totpEnabled && webauthnCredentials.length <= 1 && (
                <p className="mfa-hint">Add another factor before removing the last passkey.</p>
              )}
            </div>
            {totpEnabled && (
              <div className="mfa-panel-block">
                <label>
                  Current TOTP code
                  <input
                    className="mfa-code-input"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpDisableCode}
                    onChange={(e) => setTotpDisableCode(e.target.value)}
                    placeholder="123456"
                  />
                </label>
                <button
                  type="button"
                  onClick={onDisable2FA}
                  className="ghost mfa-inline-action"
                  disabled={auth.role === 'admin' && !webauthnEnabled}
                >
                  Disable 2FA
                </button>
                {auth.role === 'admin' && !webauthnEnabled && (
                  <p className="mfa-hint">Register a passkey before disabling TOTP.</p>
                )}
              </div>
            )}
          </div>
          )}
        </div>
      )}
    </div>
  );

  const renderMain = () => (
    <div className="page compact">
      {canViewAudit && liveSecurityIncident && (
        <section className="incident-banner critical reveal" role="alert" aria-live="assertive">
          <div>
            <p className="incident-kicker">Escalation Triggered</p>
            <h3>{liveSecurityIncident.title}</h3>
            <p className="muted">{liveSecurityIncident.hint}</p>
            <p className="muted">
              {liveSecurityIncident.criticalCount} critical signals in the last 5 minutes · triggered {formatRelativeDate(liveSecurityIncident.createdAt)}
            </p>
            {containmentEnabled && (
              <p className="incident-containment-state">
                Containment active{containmentStatus.updatedBy ? ` by ${containmentStatus.updatedBy}` : ''}
                {containmentStatus.updatedAt ? ` · ${formatRelativeDate(containmentStatus.updatedAt)}` : ''}
              </p>
            )}
            {activeSecurityIncident?.active && activeSecurityIncident?.incident?.id > 0 && (
              <p className="incident-case-state">
                Active case #{activeSecurityIncident.incident.id}
                {activeSecurityIncident.incident.openedBy ? ` · opened by ${activeSecurityIncident.incident.openedBy}` : ''}
                {activeSecurityIncident.incident.openedAt ? ` · ${formatRelativeDate(activeSecurityIncident.incident.openedAt)}` : ''}
              </p>
            )}
            {incidentSuspectSessions.length > 0 && (
              <div className="incident-sessions">
                <p className="muted">Correlated sessions (highest risk first):</p>
                <div className="incident-session-list">
                  {incidentSuspectSessions.map((session) => (
                    <button
                      key={`incident-session-${session.id}`}
                      type="button"
                      className="ghost incident-session-chip"
                      onClick={() => openAudit(session.id)}
                    >
                      Session #{session.id} · score {session.score} · {session.status}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div className="incident-actions">
            <button type="button" className="secondary" onClick={() => openAudit()}>
              Investigate now
            </button>
            {liveAlertProfile !== 'strict' && (
              <button type="button" className="ghost" onClick={() => setLiveAlertProfile('strict')}>
                Switch to strict
              </button>
            )}
            {!activeSecurityIncident?.active && (
              <button type="button" className="ghost" onClick={openIncidentCase} disabled={incidentCaseBusy}>
                {incidentCaseBusy ? 'Opening incident...' : 'Open incident case'}
              </button>
            )}
            {canManagePlatform && activeSecurityIncident?.active && (
              <button type="button" className="ghost" onClick={closeIncidentCase} disabled={incidentCaseBusy}>
                {incidentCaseBusy ? t('app.closingIncident') : t('app.closeIncidentCase')}
              </button>
            )}
            {canManagePlatform && !containmentEnabled && (
              <button type="button" className="ghost" onClick={() => setContainmentEnabled(true)} disabled={containmentBusy}>
                {containmentBusy ? 'Enabling containment...' : 'Enable containment'}
              </button>
            )}
            {canManagePlatform && containmentEnabled && (
              <button type="button" className="ghost" onClick={() => setContainmentEnabled(false)} disabled={containmentBusy}>
                {containmentBusy ? 'Updating containment...' : 'Disable containment'}
              </button>
            )}
            {canOperateSessions && activeIncidentSuspectSessions.length > 0 && (
              <button type="button" className="ghost" onClick={requestTerminateIncidentSuspects}>
                {t('app.terminateActiveSuspects', { count: activeIncidentSuspectSessions.length })}
              </button>
            )}
            <button type="button" className="ghost" onClick={dismissLiveSecurityIncident}>
              Dismiss
            </button>
          </div>
        </section>
      )}

      {incidentTerminateConfirmOpen && (
        <div className="modal-overlay" onClick={() => !incidentTerminateBusy && setIncidentTerminateConfirmOpen(false)}>
          <div className="modal-content" onClick={(event) => event.stopPropagation()}>
            <h3>Confirm Session Termination</h3>
            <p>
              {t('app.confirmTerminateBody', { count: activeIncidentSuspectSessions.length })}
            </p>
            <div className="resource-actions" style={{ marginTop: '0.9rem' }}>
              <button type="button" onClick={confirmTerminateIncidentSuspects} disabled={incidentTerminateBusy}>
                {incidentTerminateBusy ? 'Terminating...' : 'Confirm terminate'}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => setIncidentTerminateConfirmOpen(false)}
                disabled={incidentTerminateBusy}
              >
                {t('common.cancel')}
              </button>
            </div>
          </div>
        </div>
      )}

      {canViewAudit && (
        <div className="live-alert-stack" role="status" aria-live="polite">
          {liveSecurityAlerts.map((alert) => (
            <article className={`live-alert ${alert.severity}`} key={alert.key}>
              <div className="live-alert-head">
                <strong>{alert.title}</strong>
                <span className="live-alert-severity">{String(alert.severity || 'warning').toUpperCase()}</span>
                <button
                  type="button"
                  className="ghost live-alert-close"
                  onClick={() => dismissLiveSecurityAlert(alert.key)}
                >
                  Dismiss
                </button>
              </div>
              <p className="muted">{alert.hint}</p>
              <p className="muted">
                {alert.eventType} - {formatRelativeDate(alert.createdAt)}
              </p>
            </article>
          ))}
        </div>
      )}

      <header className="topbar">
        <div className="brand">
          <img src="/assets/logo-icon-dark.png" alt="EndoriumFort" className="brand-logo" />
          <div>
            <h1>{t('app.title')}</h1>
            <p>{t('app.subtitle')}</p>
          </div>
        </div>
        <div className="top-actions">
          <div className="health">
            <span className={`pill ${status}`}>{status}</span>
            <span className="detail">{detail}</span>
            <span className="pill monitor">{roleName}</span>
          </div>
          <div className="nav-actions">
            <select aria-label={t('common.language')} value={locale} onChange={(event) => setLocale(event.target.value)}>
              <option value="fr">{t('common.french')}</option>
              <option value="en">{t('common.english')}</option>
            </select>
            {canManagePlatform && (
              <button
                type="button"
                className="secondary"
                onClick={() => navigate('/admin')}
              >
                {t('app.admin')}
              </button>
            )}
            <button type="button" className="ghost" onClick={() => setChangePwOpen(true)}>
              {t('auth.changePassword')}
            </button>
            <button type="button" className="ghost icon-btn" title={darkMode ? t('auth.lightMode') : t('auth.darkMode')} onClick={toggleDarkMode}>
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button type="button" className="ghost" onClick={onLogout}>
              {t('auth.signOut')}
            </button>
          </div>
        </div>
      </header>

      <section className="mission-board reveal" aria-label={t('nav.missionBoard')}>
        <div className="mission-headline">
          <div>
            <p className="workflow-kicker">{t('app.accessWorkspace')}</p>
            <h3>{t('app.chooseResource')}</h3>
            <p>{t('app.chooseResourceHint')}</p>
          </div>
          <div className="mission-headline-actions">
            <button type="button" className="ghost" onClick={onQuickRefresh} disabled={quickRefreshing}>
              {quickRefreshing ? t('app.refreshing') : t('app.refreshData')}
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

      {canViewAudit && (
        <section className="live-alert-settings reveal" aria-label={t('nav.alertNoiseFilter')}>
          <div className="live-alert-settings-copy">
            <strong>{t('app.alertNoiseFilter')}</strong>
            <span>{t('app.alertNoiseHint')}</span>
          </div>
          <div className="live-alert-profile-tabs" role="group" aria-label={t('nav.liveAlertFilterMode')}>
            {Object.keys(LIVE_ALERT_PROFILES).map((profileKey) => (
              <button
                type="button"
                key={profileKey}
                className={`live-alert-profile-btn ${liveAlertProfile === profileKey ? 'active' : ''}`}
                onClick={() => setLiveAlertProfile(profileKey)}
              >
                {LIVE_ALERT_PROFILE_LABEL[profileKey] || profileKey}
              </button>
            ))}
          </div>
        </section>
      )}

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
              <p className="muted">{t('app.resources')}</p>
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
            <span className="pill ok">{t('app.shownCount', { count: recentSessions.length })}</span>
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
            <h3>{t('app.resources')}</h3>
            <p>{t('app.resourcesHint')}</p>
          </div>
          <div className="status-row">
            {loadingResources ? (
              <span className="pill loading">{t('common.loading')}</span>
            ) : (
              <span className="pill ok">{t('app.tilesCount', { count: resources.length })}</span>
            )}
          </div>
        </div>
        {resourceError && <InlineAlert tone="error">{resourceError}</InlineAlert>}
        <div className="resource-tiles">
          {resources.length ? (
            resources.map((resource) => {
              const protocol = String(resource?.protocol || 'ssh').toLowerCase();
              const resourceName = resource?.name || `${t('app.resource')} #${resource.id}`;
              const endpointPort = resource?.port ?? '-';
              const endpoint = `${resource?.target || t('common.notAvailable')}:${endpointPort}`;
              const policyTags = Array.from(new Set([
                ...describeAccessOutcome(resource, t),
                ...describeResourcePolicy(resource, t)
              ]));

              return (
                <button
                  type="button"
                  className="resource-tile"
                  key={resource.id}
                  onClick={() => onConnectResource(resource)}
                >
                  <div className="resource-tile-header">
                    <div
                      className="resource-thumb"
                      style={
                        resource.imageData
                          ? { backgroundImage: `url(${resource.imageData})` }
                          : resource.imageUrl
                            ? { backgroundImage: `url(${resource.imageUrl})` }
                            : undefined
                      }
                    >
                      {!(resource.imageData || resource.imageUrl) && (
                        <span className="resource-letter">
                          {resourceName[0] || 'R'}
                        </span>
                      )}
                    </div>

                    <div className="resource-info">
                      <h4 title={resourceName}>{resourceName}</h4>
                      <p className="resource-endpoint">
                        <span className="resource-protocol-chip">{protocol.toUpperCase()}</span>
                        <span className="resource-endpoint-value">{endpoint}</span>
                      </p>
                    </div>

                    <span className={`resource-launch-pill ${protocol === 'agent' ? 'agent' : 'direct'}`}>
                      {protocol === 'agent' ? t('app.launch') : t('app.connectLower')}
                    </span>
                  </div>

                  {resource.description && (
                    <p className="resource-description">{resource.description}</p>
                  )}

                  <div className="resource-tag-row">
                    {resource.hasCredentials && (
                      <span className="resource-tag resource-tag-vault" title={t('app.vaultStored')}>
                        {t('app.vault')}
                      </span>
                    )}
                    {policyTags.map((item) => (
                      <span className="resource-tag resource-tag-policy" key={`policy-${resource.id}-${item}`}>
                        {item}
                      </span>
                    ))}
                  </div>
                </button>
              );
            })
          ) : (
            <EmptyState title={t('app.noResourcesYet')} message={t('app.noResourcesMessage')} />
          )}
        </div>
      </section>

      {(mainTab === 'sessions' || mainTab === 'audit') && (
      <section className="main-grid">
        {mainTab === 'sessions' && (
        <div className="panel reveal">
          <div className="panel-header">
            <div>
              <h3>{t('app.sessionPanelTitle')}</h3>
              <p>{t('app.sessionPanelHint')}</p>
            </div>
            <div className="status-row">
              {loadingSessions ? (
                <span className="pill loading">{t('common.loading')}</span>
              ) : (
                <span className="pill ok">{t('app.activeCount', { count: activeSessions.length })}</span>
              )}
            </div>
          </div>
          {sessionError && <p className="error">{sessionError}</p>}

          {canManagePlatform && (
            <div style={{ marginBottom: '1rem' }}>
              <div className="panel-header" style={{ marginBottom: '0.7rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem' }}>{t('app.pendingApprovals')}</h3>
                  <p>{t('app.pendingApprovalsHint')}</p>
                </div>
                <span className={`pill ${pendingAccessApprovals.length ? 'loading' : 'ok'}`}>
                  {t('admin.pendingCount', { count: pendingAccessApprovals.length })}
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
                          {t('admin.approve')}
                        </button>
                        <button
                          type="button"
                          className="ghost"
                          onClick={() => onDenyAccessRequest(request.id)}
                        >
                          {t('admin.deny')}
                        </button>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="muted">{t('app.noPendingApprovals')}</p>
                )}
              </div>
            </div>
          )}

          <div className="watchlist-panel">
            <div className="slo-grid">
              <article className="slo-card">
                <span>{t('app.completionRate')}</span>
                <strong>{sessionSlo.completionRate}%</strong>
                <p className="muted">{t('app.terminatedSessionsTotal')}</p>
              </article>
              <article className="slo-card">
                <span>{t('app.averageDuration')}</span>
                <strong>{sessionSlo.avgDurationMin} min</strong>
                <p className="muted">{t('app.basedOnClosedHistory')}</p>
              </article>
              <article className="slo-card">
                <span>{t('app.staleActiveSessions')}</span>
                <strong>{sessionSlo.staleActive}</strong>
                <p className="muted">{t('app.activeOverHours')}</p>
              </article>
            </div>
            <div className="panel-header" style={{ marginBottom: '0.35rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem' }}>{t('app.criticalSessionWatchlist')}</h3>
                <p>{t('app.watchlistHint')}</p>
              </div>
              <span className={`pill ${watchedSessions.length ? 'loading' : 'ok'}`}>
                {t('app.watchedCount', { count: watchedSessions.length })}
              </span>
            </div>
            {watchlistAlerts.length > 0 && (
              <div className="watch-alert-list">
                {watchlistAlerts.map((alert) => (
                  <article key={alert.key} className="watch-alert-item">
                    <p>{alert.message}</p>
                    <button type="button" className="ghost" onClick={() => dismissWatchAlert(alert.key)}>
                      {t('app.dismiss')}
                    </button>
                  </article>
                ))}
              </div>
            )}
            {watchedSessions.length ? (
              <div className="watchlist-grid">
                {watchedSessions.map((session) => (
                  <article key={`watch-${session.id}`} className="watchlist-item">
                    <strong>#{session.id} {session.user} -&gt; {session.target}</strong>
                    <span className={`pill ${session.status}`}>{session.status}</span>
                    <p className="muted">Opened {formatRelativeDate(session.createdAt)}</p>
                  </article>
                ))}
              </div>
            ) : (
              <p className="muted">{t('app.noWatchedSessions')}</p>
            )}
          </div>

          {(sessionEvidenceLoading || sessionEvidencePack || sessionEvidenceError) && (
            <div className="watchlist-panel">
              <div className="panel-header" style={{ marginBottom: '0.5rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem' }}>Evidence Pack</h3>
                  <p>Signed JIT access proof for the selected session.</p>
                </div>
              </div>
              {sessionEvidenceLoading && <p className="muted">Loading evidence pack...</p>}
              {sessionEvidenceError && <p className="error">{sessionEvidenceError}</p>}
              {sessionEvidencePack && (
                <div className="resource-list">
                  <article className="resource-row">
                    <div>
                      <h4>Session #{sessionEvidencePack.session?.id}</h4>
                      <p className="muted">
                        Digest: <code>{sessionEvidencePack.digest}</code>
                      </p>
                      <p className="muted">
                        Signature: <code>{sessionEvidencePack.signature}</code>
                      </p>
                      <p className="muted">
                        Grant #{sessionEvidencePack.accessGrant?.id || 'n/a'} • Policy #{sessionEvidencePack.accessGrant?.policyId || 0}
                      </p>
                    </div>
                  </article>
                </div>
              )}
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
                  <div className="session-card-tools">
                    <button
                      type="button"
                      className={watchedSessionIds.includes(Number(session.id)) ? 'secondary' : 'ghost'}
                      onClick={() => toggleWatchSession(session.id)}
                    >
                      {watchedSessionIds.includes(Number(session.id)) ? t('app.pinned') : t('app.pin')}
                    </button>
                    <span className={`pill ${session.status}`}>
                      {session.status}
                    </span>
                  </div>
                </header>
                <p className="session-route">
                  <strong>{session.user}</strong>
                  <span className="arrow">{t('app.to')}</span>
                  <strong>{session.target}</strong>
                </p>
                <div className="session-route-hints">
                  <span className={`pill ${sessionRelayHints[session.id]?.route === 'relay' ? 'loading' : 'ready'}`}>
                    {sessionRelayHints[session.id]?.route === 'relay' ? t('app.viaRelay') : t('app.directRoute')}
                  </span>
                  {sessionRelayHints[session.id]?.route === 'relay' && sessionRelayHints[session.id]?.relayLabel && (
                    <span className="muted session-relay-label">
                      {sessionRelayHints[session.id].relayLabel} ({sessionRelayHints[session.id].relayStatus || 'offline'})
                    </span>
                  )}
                </div>
                <div className="session-meta">
                  <span>{t('app.openedAt', { value: session.createdAt })}</span>
                  {session.accessGrantId ? (
                    <span>Grant #{session.accessGrantId}</span>
                  ) : null}
                  {session.credentialSource ? (
                    <span>{session.credentialSource}</span>
                  ) : null}
                  {session.terminatedAt && (
                    <span>{t('app.closedAt', { value: session.terminatedAt })}</span>
                  )}
                </div>
                <div className="session-actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => onTerminate(session.id)}
                    disabled={session.status !== 'active' || !canOperateSessions}
                  >
                    {t('app.terminate')}
                  </button>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => openAudit(session.id)}
                  >
                    {t('app.openAudit')}
                  </button>
                  {canViewAudit && (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => onOpenSessionDna(session.id)}
                    >
                      {t('app.sessionDna')}
                    </button>
                  )}
                  {canViewAudit && (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => onOpenSessionEvidence(session.id)}
                    >
                      Evidence pack
                    </button>
                  )}
                  {canViewAudit && (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => openRecordings(session.id)}
                    >
                      {t('app.recordings')}
                    </button>
                  )}
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => openLiveSession(session)}
                    disabled={session.status !== 'active' || !canOperateSessions}
                  >
                    {t('app.openLive')}
                  </button>
                  {canViewAudit &&
                    session.status === 'active' && (
                      <button
                        type="button"
                        className="ghost shadow-btn"
                        onClick={() => openShadow(session)}
                        title={t('app.shadowObserve')}
                      >
                        👁 {t('app.shadowTitle')}
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
                <h3>{t('app.auditLog')}</h3>
                <p>{t('app.auditLogHint')}</p>
              </div>
              <div className="status-row">
                {loadingAudit ? (
                  <span className="pill loading">{t('common.loading')}</span>
                ) : (
                  <span className="pill ok">{t('app.eventsCount', { count: filteredAuditItems.length })}</span>
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
                {t('common.refresh')}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={exportFilteredAuditCsv}
                disabled={!filteredAuditItems.length}
              >
                {t('app.exportCsv')}
              </button>
              {auditFilter && (
                <button
                  type="button"
                  className="ghost"
                  onClick={() => setAuditFilter(null)}
                >
                  {t('app.clearFilter')}
                </button>
              )}
              <button type="button" className="ghost" onClick={() => setAuditFilter(null)}>
                {t('app.clearView')}
              </button>
            </div>
            <div className="audit-search-row">
              <input
                type="text"
                placeholder={t('app.searchEvents')}
                value={auditSearchQuery}
                onChange={(e) => setAuditSearchQuery(e.target.value)}
                style={{ flex: 1, maxWidth: '280px' }}
              />
              <select
                value={auditTypeFilter}
                onChange={(e) => setAuditTypeFilter(e.target.value)}
                style={{ maxWidth: '200px' }}
              >
                <option value="">{t('app.allTypes')}</option>
                <option value="auth.login">{t('app.login')}</option>
                <option value="auth.logout">{t('app.logout')}</option>
                <option value="auth.login.failure">{t('app.loginFailure')}</option>
                <option value="session.create">{t('app.sessionCreate')}</option>
                <option value="session.terminate">{t('app.sessionTerminate')}</option>
                <option value="session.close">{t('app.sessionClose')}</option>
                <option value="resource">{t('app.resource')}</option>
                <option value="user">{t('admin.users')}</option>
                <option value="credential">{t('app.credential')}</option>
                <option value="tunnel">{t('app.tunnel')}</option>
              </select>
            </div>
            {auditError && <p className="error">{auditError}</p>}
            {!canViewAudit && (
              <p className="muted">{t('app.auditorRoleHint')}</p>
            )}
            {canViewAudit && (
              <div className="audit-list">
                {filteredAuditItems.length ? (
                  filteredAuditItems.map((item) => (
                    <article className="audit-item" key={item.id}>
                      <div>
                        <h4>{item.type}</h4>
                        <p className="muted">
                          {renderAuditDetail(item) || t('app.noSessionData')}
                        </p>
                      </div>
                      <div className="audit-meta">
                        <span className="muted">{item.actor}</span>
                        <span className="muted">{item.createdAt}</span>
                      </div>
                    </article>
                  ))
                ) : (
                  <p className="muted">{t('app.noAuditEvents')}</p>
                )}
              </div>
            )}
          </div>
        )}
      </section>
      )}

      {/* Recordings panel */}
      {mainTab === 'recordings' && canViewRecordings && (
        <Suspense
          fallback={(
            <SectionCard title={t('recordings.title')} subtitle={t('app.loadingRecordingsView')}>
              <EmptyState title={t('common.loading')} message={t('app.preparingReplayWorkspace')} />
            </SectionCard>
          )}
        >
          <RecordingsPanel
            loadingRecordings={loadingRecordings}
            recordings={recordings}
            recordingsError={recordingsError}
            loadRecordings={loadRecordings}
            closePlayer={closePlayer}
            castData={castData}
            castRecordingId={castRecordingId}
            playerPlaying={playerPlaying}
            startPlayer={startPlayer}
            stopPlayer={stopPlayer}
            playerIndex={playerIndex}
            playerEvents={playerEvents}
            playerTermRef={playerTermRef}
            onPlayRecording={onPlayRecording}
          />
        </Suspense>
      )}

      {mainTab === 'sessions' && (
      <section className="panel terminal-panel reveal">
        <div className="panel-header">
          <div>
            <h3>{t('app.liveSshConsole')}</h3>
            <p>{t('app.liveSshConsoleHint')}</p>
          </div>
          <span className={`pill ${terminalStatus === 'live' ? 'ok' : 'loading'}`}>
            {terminalStatus}
          </span>
        </div>
        <div className="terminal-controls">
          <div>
            <span className="muted">{t('app.sessions')}</span>
            <h4>
              {activeTerminalSession
                ? `#${activeTerminalSession.id} ${activeTerminalSession.target}`
                : t('auth.noSessionSelected')}
            </h4>
          </div>
          <label>
            {t('app.sshPassword')}
            <input
              type="password"
              value={sshPassword}
              onChange={(event) => setSshPassword(event.target.value)}
              placeholder={t('auth.enterSshPassword')}
            />
          </label>
          <button type="button" onClick={connectTerminal}>
            {t('auth.connect')}
          </button>
        </div>
        <div className="snippet-studio">
          <div className="snippet-studio-head">
            <h4>{t('app.sshSnippetsStudio')}</h4>
            <p>{t('app.sshSnippetsHint')}</p>
          </div>
          <div className="snippet-grid">
            {sshSnippetLibrary.map((snippet) => (
              <article key={snippet.id} className="snippet-card">
                <strong>{snippet.label}</strong>
                <code>{snippet.command}</code>
                <div className="snippet-actions">
                  <button type="button" className="ghost" onClick={() => sendSnippetToTerminal(snippet, false)}>
                    {t('app.inject')}
                  </button>
                  <button type="button" onClick={() => sendSnippetToTerminal(snippet, true)}>
                    {t('app.run')}
                  </button>
                  {snippet.custom && (
                    <button
                      type="button"
                      className="danger"
                      onClick={() => removeCustomSnippet(snippet.id)}
                    >
                      Delete
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
          <div className="snippet-builder">
            <label>
              {t('app.snippetLabel')}
              <input
                type="text"
                value={snippetLabel}
                onChange={(event) => setSnippetLabel(event.target.value)}
                placeholder="Example: App logs"
              />
            </label>
            <label>
              {t('app.command')}
              <input
                type="text"
                value={snippetCommand}
                onChange={(event) => setSnippetCommand(event.target.value)}
                placeholder="tail -n 80 /var/log/app.log"
              />
            </label>
            <button type="button" className="secondary" onClick={addCustomSnippet}>
              {t('app.saveSnippet')}
            </button>
          </div>
        </div>
        {terminalError && <p className="error">{terminalError}</p>}
        {terminalInfo && <p className="muted">{terminalInfo}</p>}
        <div className="terminal-shell" ref={terminalRef} />
      </section>
      )}

      {mainTab === 'sessions' && inlineWebResource && (
      <section className="panel reveal" style={{ marginBottom: '24px' }}>
          <div className="panel-header">
            <div>
              <h3>{t('app.embeddedWebAccess')}</h3>
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
              {t('common.close')}
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

      {vncViewerSession && (
        <VncViewerModal
          session={vncViewerSession}
          onClose={() => setVncViewerSession(null)}
        />
      )}

      {/* Shadow session panel */}
      {mainTab === 'sessions' && shadowSession && (
        <section className="panel terminal-panel shadow-panel reveal">
            <div className="panel-header">
              <div>
              <h3>👁 {t('app.shadowTitle')} - Session #{shadowSession.id}</h3>
              <p>
                {t('app.readOnlyObservation')}{' '}
                <strong>{shadowSession.user}</strong> → <strong>{shadowSession.target}</strong>
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span className={`pill ${shadowStatus === 'live' ? 'ok' : shadowStatus === 'error' ? 'error' : 'loading'}`}>
                {shadowStatus}
              </span>
              <button type="button" className="secondary" onClick={closeShadow}>
                {t('common.close')}
              </button>
            </div>
          </div>
          <div className="terminal-shell shadow-terminal" ref={shadowTermRef} />
        </section>
      )}

      {accessPromptResource && (
        <div
          className="modal-overlay"
          onClick={closeAccessPrompt}
        >
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>
              {accessPromptMode === 'request'
                ? t('app.approvalRequestRequired')
                : t('app.connectionJustificationRequired')}
            </h3>
            <p className="muted" style={{ marginTop: 0 }}>
              {accessPromptMode === 'request'
                ? t('app.approvalWorkflowRequired', { name: accessPromptResource.name })
                : containmentEnabled
                  ? t('app.containmentReasonRequired', { name: accessPromptResource.name })
                  : t('app.accessReasonRequired', { name: accessPromptResource.name })}
            </p>
            <div className="policy-chip-row" style={{ marginBottom: '0.8rem' }}>
              {describeAccessOutcome(accessPromptResource, t).map((item) => (
                <span className="policy-chip" key={`access-prompt-${item}`}>{item}</span>
              ))}
            </div>
            {containmentEnabled && accessPromptMode === 'connect' && containmentStatus.reason && (
              <p className="muted" style={{ marginTop: 0 }}>
                {t('app.containmentContext', { value: containmentStatus.reason })}
              </p>
            )}
            <form onSubmit={onSubmitAccessPrompt}>
              <div className="risk-preview-box">
                <strong>{t('app.riskPreview')}</strong>
                {riskPreviewLoading && <p className="muted">{t('app.calculatingRiskScore')}</p>}
                {riskPreviewError && <p className="error">{riskPreviewError}</p>}
                {riskPreview && (
                  <>
                    <p className="muted" style={{ marginBottom: '0.35rem' }}>
                      {t('app.score', { value: riskPreview.score, risk: riskPreview.effectiveRiskLevel })}
                    </p>
                    <p className="muted" style={{ marginBottom: '0.35rem' }}>
                      {[
                        riskPreview.justificationRequired ? 'justification' : null,
                        riskPreview.ticketRequired ? 'ticket' : null,
                        riskPreview.approvalRequired ? 'approval' : null,
                        riskPreview.mfaRequirement && riskPreview.mfaRequirement !== 'any'
                          ? `mfa:${riskPreview.mfaRequirement}`
                          : null,
                        riskPreview.routingConstraint && riskPreview.routingConstraint !== 'any'
                          ? `route:${riskPreview.routingConstraint}`
                          : null,
                        riskPreview.maxDurationSeconds ? `ttl:${riskPreview.maxDurationSeconds}s` : null
                      ].filter(Boolean).join(' • ')}
                    </p>
                    <p className="muted" style={{ margin: 0 }}>
                      {Array.isArray(riskPreview.factors)
                        ? riskPreview.factors.join(' - ')
                        : t('app.noFactors')}
                    </p>
                  </>
                )}
              </div>
              <div className="playbook-strip">
                <div>
                  <strong>{t('app.accessPlaybook')}</strong>
                  <p className="muted">
                    {currentAccessPlaybook
                      ? t('app.playbookSavedAt', { value: new Date(currentAccessPlaybook.updatedAt || Date.now()).toLocaleString(locale) })
                      : t('app.noPlaybookYet')}
                  </p>
                </div>
                <div className="playbook-actions">
                  <button type="button" className="ghost" onClick={applyCurrentAccessPlaybook}>
                    {t('app.apply')}
                  </button>
                  <button type="button" className="secondary" onClick={saveCurrentAccessPlaybook}>
                    {t('common.save')}
                  </button>
                  {currentAccessPlaybook && (
                    <button type="button" className="danger" onClick={deleteCurrentAccessPlaybook}>
                      {t('common.delete')}
                    </button>
                  )}
                </div>
              </div>
              <label>
                {t('app.accessReason')}
                <input
                  type="text"
                  value={accessPromptReason}
                  onChange={(event) => setAccessPromptReason(event.target.value)}
                  placeholder={t('app.accessReasonPlaceholder')}
                  required
                />
              </label>
              <label>
                {t('app.ticketChangeId')}
                <input
                  type="text"
                  value={accessPromptTicketId}
                  onChange={(event) => setAccessPromptTicketId(event.target.value)}
                  placeholder={t('app.ticketChangePlaceholder')}
                />
              </label>
              <label>
                {t('app.sessionPurpose')} {(String(accessPromptResource.riskLevel || '').toLowerCase() === 'high' ||
                String(accessPromptResource.riskLevel || '').toLowerCase() === 'critical')
                  ? t('app.requiredForHighRisk')
                  : t('app.optionalLabel')}
                <input
                  type="text"
                  value={accessPromptPurpose}
                  onChange={(event) => setAccessPromptPurpose(event.target.value)}
                  placeholder={t('app.sessionPurposePlaceholder')}
                  required={
                    String(accessPromptResource.riskLevel || '').toLowerCase() === 'high' ||
                    String(accessPromptResource.riskLevel || '').toLowerCase() === 'critical'
                  }
                />
              </label>
              <label>
                {t('app.purposeEvidence')}
                <input
                  type="text"
                  value={accessPromptPurposeEvidence}
                  onChange={(event) => setAccessPromptPurposeEvidence(event.target.value)}
                  placeholder={t('app.purposeEvidencePlaceholder')}
                />
              </label>
              <div style={{ display: 'flex', gap: '0.8rem', marginTop: '0.8rem' }}>
                <button type="submit">
                  {accessPromptMode === 'request' ? t('app.submitRequest') : t('app.continue')}
                </button>
                <button
                  type="button"
                  className="ghost"
                  onClick={closeAccessPrompt}
                >
                  {t('common.cancel')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {sessionDnaLoading && (
        <div className="modal-overlay" onClick={() => setSessionDnaLoading(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>{t('app.sessionDna')}</h3>
            <p className="muted">{t('app.loadingChain')}</p>
          </div>
        </div>
      )}

      {(sessionDna || sessionDnaError) && !sessionDnaLoading && (
        <div
          className="modal-overlay"
          onClick={() => {
            setSessionDna(null);
            setSessionDnaError('');
          }}
        >
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>{t('app.sessionDna')} {sessionDna?.sessionId ? `#${sessionDna.sessionId}` : ''}</h3>
            {sessionDnaError && <p className="error">{sessionDnaError}</p>}
            {sessionDna && (
              <>
                <p className="muted" style={{ marginTop: 0 }}>
                  {t('app.integrity', { value: sessionDna.verified ? t('app.verified') : t('app.mismatchDetected') })}
                </p>
                <div className="audit-timeline" style={{ maxHeight: '320px', overflowY: 'auto' }}>
                  {(sessionDna.entries || []).length ? (
                    sessionDna.entries.map((entry) => (
                      <article key={`dna-${entry.id}`}>
                        <strong>{entry.eventType}</strong>
                        <p>#{entry.id} - {entry.createdAt}</p>
                        <p>hash: {String(entry.chainHash || '').slice(0, 20)}...</p>
                      </article>
                    ))
                  ) : (
                    <p className="muted">{t('app.noDnaEntries')}</p>
                  )}
                </div>
              </>
            )}
            <div style={{ marginTop: '0.8rem' }}>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setSessionDna(null);
                  setSessionDnaError('');
                }}
              >
                {t('common.close')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Agent launch modal */}
      {agentModal && (
        <div className="modal-overlay" onClick={() => {
          clearAgentLaunchWatcher();
          setAgentModal(null);
        }}>
          <div className="modal-content agent-modal" onClick={(e) => e.stopPropagation()}>
            <div className="agent-modal-header">
              <span className="agent-icon">🚀</span>
              <div>
                <h3>{t('app.agentTunnel')}</h3>
                <p className="muted">{t('app.agentLocalConnection')}</p>
              </div>
            </div>
            <div className="agent-modal-info">
              <div className="agent-info-row">
                <span className="agent-label">{t('app.resourceLabel')}</span>
                <span className="agent-value">{agentModal.resource.name}</span>
              </div>
              <div className="agent-info-row">
                <span className="agent-label">{t('app.targetLabel')}</span>
                <span className="agent-value">{agentModal.resource.target}:{agentModal.resource.port}</span>
              </div>
              <div className="agent-info-row">
                <span className="agent-label">{t('app.localPort')}</span>
                <span className="agent-value">127.0.0.1:{agentModal.port}</span>
              </div>
            </div>
            <div className="agent-command-block">
              <label className="agent-label">{t('app.fallbackCommand')}</label>
              <div className="agent-command-row">
                <code className="agent-command">{agentModal.command}</code>
                <button
                  type="button"
                  className="secondary"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(agentModal.command);
                      setAgentModal((prev) => (prev ? { ...prev, copied: 'ok' } : prev));
                    } catch (_) {
                      setAgentModal((prev) => (prev ? { ...prev, copied: 'fail' } : prev));
                    }
                    setTimeout(() => setAgentModal((prev) => prev ? ({ ...prev, copied: 'idle' }) : null), 2000);
                  }}
                >
                  {agentModal.copied === 'ok' ? `✓ ${t('app.copied')}` : agentModal.copied === 'fail' ? `❌ ${t('app.copyFailed')}` : `📋 ${t('app.copy')}`}
                </button>
              </div>
            </div>
            <div className="agent-command-block">
              <label className="agent-label">{t('app.deepLink')}</label>
              <div className="agent-command-row">
                <code className="agent-command">{agentModal.deepLink}</code>
                <button
                  type="button"
                  className="secondary"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(agentModal.deepLink);
                      setAgentModal((prev) => (prev ? { ...prev, linkCopied: 'ok' } : prev));
                    } catch (_) {
                      setAgentModal((prev) => (prev ? { ...prev, linkCopied: 'fail' } : prev));
                    }
                    setTimeout(() => setAgentModal((prev) => prev ? ({ ...prev, linkCopied: 'idle' }) : null), 2000);
                  }}
                >
                  {agentModal.linkCopied === 'ok' ? `✓ ${t('app.copied')}` : agentModal.linkCopied === 'fail' ? `❌ ${t('app.copyFailed')}` : `📋 ${t('app.copyLink')}`}
                </button>
              </div>
            </div>
            <div className="agent-modal-tip">
              {agentModal.openInBrowser ? (
                <p>💡 {t('app.agentOpenBrowserTip', { value: agentModal.localUrl })} <a href={agentModal.localUrl} target="_blank" rel="noreferrer">{agentModal.localUrl}</a>.</p>
              ) : (
                <p>💡 {t('app.agentClientTip', { protocol: String(agentModal.resource?.protocol || '').toUpperCase(), value: agentModal.localEndpoint })}</p>
              )}
              {agentModal.launchState === 'opening' && (
                <p className="muted">{t('app.openingAgentApp')}</p>
              )}
              {agentModal.launchState === 'fallback' && (
                <>
                  <p className="error" style={{ marginBottom: '0.45rem' }}>
                    {t('app.missingProtocolHandler')}
                  </p>
                  <p className="muted" style={{ marginBottom: '0.45rem' }}>
                    {t('app.quickInstall', { platform: agentModal.installGuide?.platform || 'OS' })}
                  </p>
                  <div className="agent-command-row">
                    <code className="agent-command">{agentModal.installGuide?.command}</code>
                    <button
                      type="button"
                      className="secondary"
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(agentModal.installGuide?.command || '');
                          setAgentModal((prev) => (prev ? { ...prev, installCopied: 'ok' } : prev));
                        } catch (_) {
                          setAgentModal((prev) => (prev ? { ...prev, installCopied: 'fail' } : prev));
                        }
                        setTimeout(() => setAgentModal((prev) => prev ? ({ ...prev, installCopied: 'idle' }) : null), 2000);
                      }}
                    >
                      {agentModal.installCopied === 'ok' ? `✓ ${t('app.copied')}` : agentModal.installCopied === 'fail' ? `❌ ${t('app.copyFailed')}` : `📋 ${t('app.copyInstall')}`}
                    </button>
                  </div>
                </>
              )}
            </div>
            <div className="agent-modal-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => launchAgentDeepLink(agentModal.deepLink)}
              >
                🚀 {t('app.openWithAgent')}
              </button>
              <button
                type="button"
                onClick={() => {
                  const randomPort = 10000 + Math.floor(Math.random() * 50000);
                  const launchPayload = buildAgentLaunchPayload(agentModal.resource, randomPort);
                  setAgentModal((prev) => ({ ...prev, port: randomPort, copied: 'idle', linkCopied: 'idle', installCopied: 'idle', launchState: 'idle', ...launchPayload }));
                }}
                className="ghost"
              >
                🔄 {t('app.newPort')}
              </button>
              <button type="button" className="ghost" onClick={() => {
                clearAgentLaunchWatcher();
                setAgentModal(null);
              }}>{t('app.closeLabel')}</button>
            </div>
          </div>
        </div>
      )}

      {/* Change password modal */}
      {changePwOpen && (
        <div className="modal-overlay" onClick={() => setChangePwOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>{t('auth.changePassword')}</h3>
            <form onSubmit={onChangePassword}>
              <label>
                {t('auth.currentPassword')}
                <input type="password" value={changePwCurrent}
                  onChange={(e) => setChangePwCurrent(e.target.value)} required />
              </label>
              <label>
                {t('auth.newPassword')}
                <input type="password" value={changePwNew}
                  onChange={(e) => setChangePwNew(e.target.value)} required
                  placeholder={t('auth.passwordPlaceholder')} />
              </label>
              <label>
                {t('auth.confirmNewPassword')}
                <input type="password" value={changePwConfirm}
                  onChange={(e) => setChangePwConfirm(e.target.value)} required />
              </label>
              {changePwError && <p className="error">{changePwError}</p>}
              {changePwSuccess && <p className="success">{changePwSuccess}</p>}
              <div style={{display:'flex',gap:'0.8rem',marginTop:'0.8rem'}}>
                <button type="submit">{t('auth.change')}</button>
                <button type="button" className="ghost" onClick={() => {
                  setChangePwOpen(false); setChangePwError(''); setChangePwSuccess('');
                  setChangePwCurrent(''); setChangePwNew(''); setChangePwConfirm('');
                }}>{t('common.cancel')}</button>
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
    return (
      <>
        {renderAdmin()}
        {renderBootstrapOverlay()}
      </>
    );
  }
  return (
    <>
      {renderMain()}
      {renderBootstrapOverlay()}
    </>
  );
}

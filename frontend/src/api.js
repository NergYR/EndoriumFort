let authToken = (() => {
  try {
    const saved = localStorage.getItem('endoriumfort_auth');
    if (saved) {
      const parsed = JSON.parse(saved);
      return parsed.token || '';
    }
  } catch (_) {}
  return '';
})();

let lastUnauthorizedAt = 0;

function notifyUnauthorized() {
  const now = Date.now();
  if (now - lastUnauthorizedAt < 1500) {
    return;
  }
  lastUnauthorizedAt = now;
  authToken = '';
  try {
    localStorage.removeItem('endoriumfort_auth');
  } catch (_) {}
  try {
    window.dispatchEvent(new CustomEvent('endoriumfort:unauthorized'));
  } catch (_) {}
}

async function ensureResponseOk(response, fallbackMessage) {
  if (response.status === 401) {
    notifyUnauthorized();
    throw new Error('Session expired. Please login again.');
  }
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || fallbackMessage);
  }
}

export function setAuthToken(token) {
  authToken = token || '';
}

function withAuthHeaders(headers = {}) {
  if (!authToken) {
    return headers;
  }
  return {
    ...headers,
    Authorization: `Bearer ${authToken}`
  };
}

export async function login(payload) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Login failed');
  }
  return response.json();
}

export async function logout() {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Logout failed');
  return response.json();
}

export async function changePassword(currentPassword, newPassword, options = {}) {
  const response = await fetch('/api/auth/change-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({
      currentPassword,
      newPassword,
      keepCurrentSession: !!options.keepCurrentSession
    })
  });
  await ensureResponseOk(response, 'Failed to change password');
  return response.json();
}

export async function fetchBootstrapStatus() {
  const response = await fetch('/api/auth/bootstrap-status', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch bootstrap status');
  return response.json();
}

export async function fetchHealth() {
  const response = await fetch('/api/health');
  if (!response.ok) {
    throw new Error('Health check failed');
  }
  return response.json();
}

export async function fetchSessions() {
  const response = await fetch('/api/sessions', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch sessions');
  return response.json();
}

export async function createSession(payload) {
  const response = await fetch('/api/sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create session');
  return response.json();
}

export async function previewSessionRisk(payload) {
  const response = await fetch('/api/sessions/risk-preview', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to preview session risk');
  return response.json();
}

export async function fetchSessionDna(sessionId) {
  const response = await fetch(`/api/sessions/${sessionId}/dna`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch session DNA');
  return response.json();
}

export async function fetchSessionEvidencePack(sessionId) {
  const response = await fetch(`/api/evidence-packs/sessions/${sessionId}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch evidence pack');
  return response.json();
}

export async function terminateSession(sessionId) {
  const response = await fetch(`/api/sessions/${sessionId}/terminate`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to terminate session');
  return response.json();
}

export async function startSessionElevation(sessionId, payload = {}) {
  const response = await fetch(`/api/sessions/${sessionId}/elevation/start`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to start session elevation');
  return response.json();
}

export async function endSessionElevation(sessionId, payload = {}) {
  const response = await fetch(`/api/sessions/${sessionId}/elevation/end`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to end session elevation');
  return response.json();
}

export async function reviewSessionGoal(sessionId, payload = {}) {
  const response = await fetch(`/api/sessions/${sessionId}/goal-review`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to review session goal');
  return response.json();
}

export async function fetchAudit() {
  const response = await fetch('/api/audit', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch audit log');
  return response.json();
}

export async function fetchSecurityAlerts(sinceId = 0) {
  const response = await fetch(`/api/security/alerts?sinceId=${Number(sinceId) || 0}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch security alerts');
  return response.json();
}

export async function reportSecurityIncidentEscalation(payload) {
  const response = await fetch('/api/security/incidents/escalate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to report security incident escalation');
  return response.json();
}

export async function fetchContainmentStatus() {
  const response = await fetch('/api/security/containment', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch containment status');
  return response.json();
}

export async function setContainmentMode(payload) {
  const response = await fetch('/api/security/containment', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to update containment mode');
  return response.json();
}

export async function fetchActiveSecurityIncident() {
  const response = await fetch('/api/security/incidents/active', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch active incident');
  return response.json();
}

export async function openSecurityIncident(payload) {
  const response = await fetch('/api/security/incidents/open', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to open security incident');
  return response.json();
}

export async function closeSecurityIncident(payload) {
  const response = await fetch('/api/security/incidents/close', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to close security incident');
  return response.json();
}

export async function fetchResources() {
  const response = await fetch('/api/resources', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch resources');
  return response.json();
}

export async function createResource(payload) {
  const response = await fetch('/api/resources', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create resource');
  return response.json();
}

export async function updateResource(resourceId, payload) {
  const response = await fetch(`/api/resources/${resourceId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to update resource');
  return response.json();
}

export async function deleteResource(resourceId) {
  const response = await fetch(`/api/resources/${resourceId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to delete resource');
  return response.json();
}

export async function fetchUsers() {
  const response = await fetch('/api/users', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch users');
  return response.json();
}

export async function createUser(payload) {
  const response = await fetch('/api/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create user');
  return response.json();
}

export async function updateUser(userId, payload) {
  const response = await fetch(`/api/users/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to update user');
  return response.json();
}

export async function deleteUser(userId) {
  const response = await fetch(`/api/users/${userId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to delete user');
  return response.json();
}

export async function getUserResourcePermissions(userId) {
  const response = await fetch(`/api/users/${userId}/resources`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch permissions');
  return response.json();
}

export async function grantResourcePermission(userId, resourceId) {
  const response = await fetch(`/api/users/${userId}/resources/${resourceId}`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to grant permission');
  return response.json();
}

export async function revokeResourcePermission(userId, resourceId) {
  const response = await fetch(`/api/users/${userId}/resources/${resourceId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to revoke permission');
  return response.json();
}

export async function getUserAccessProfiles(userId) {
  const response = await fetch(`/api/users/${userId}/access-profiles`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch access profiles');
  return response.json();
}

export async function grantAccessProfile(userId, profileId) {
  const response = await fetch(`/api/users/${userId}/access-profiles/${profileId}`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to assign access profile');
  return response.json();
}

export async function revokeAccessProfile(userId, profileId) {
  const response = await fetch(`/api/users/${userId}/access-profiles/${profileId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to revoke access profile');
  return response.json();
}

export async function fetchAccessPolicies() {
  const response = await fetch('/api/access-policies', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch access policies');
  return response.json();
}

export async function createAccessPolicy(payload) {
  const response = await fetch('/api/access-policies', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create access policy');
  return response.json();
}

export async function updateAccessPolicy(policyId, payload) {
  const response = await fetch(`/api/access-policies/${policyId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to update access policy');
  return response.json();
}

export async function deleteAccessPolicy(policyId) {
  const response = await fetch(`/api/access-policies/${policyId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to delete access policy');
  return response.json();
}

export async function fetchAccessProfiles() {
  const response = await fetch('/api/access-profiles', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch access profiles');
  return response.json();
}

export async function createAccessProfile(payload) {
  const response = await fetch('/api/access-profiles', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create access profile');
  return response.json();
}

export async function updateAccessProfile(profileId, payload) {
  const response = await fetch(`/api/access-profiles/${profileId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to update access profile');
  return response.json();
}

export async function deleteAccessProfile(profileId) {
  const response = await fetch(`/api/access-profiles/${profileId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to delete access profile');
  return response.json();
}

export async function fetchAccessGrants() {
  const response = await fetch('/api/access-grants', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch access grants');
  return response.json();
}

// ── 2FA / TOTP ───────────────────────────────────────────────────────

export async function setup2FA() {
  const response = await fetch('/api/auth/setup-2fa', {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to setup 2FA');
  return response.json();
}

export async function verify2FA(code) {
  const response = await fetch('/api/auth/verify-2fa', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ code })
  });
  await ensureResponseOk(response, 'Failed to verify 2FA');
  return response.json();
}

export async function disable2FA(code) {
  const response = await fetch('/api/auth/disable-2fa', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ code })
  });
  await ensureResponseOk(response, 'Failed to disable 2FA');
  return response.json();
}

export async function get2FAStatus() {
  const response = await fetch('/api/auth/2fa-status', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch 2FA status');
  return response.json();
}

export async function beginWebAuthnRegistration(payload = {}) {
  const response = await fetch('/api/auth/webauthn/register/options', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to start passkey registration');
  return response.json();
}

export async function verifyWebAuthnRegistration(payload) {
  const response = await fetch('/api/auth/webauthn/register/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to verify passkey registration');
  return response.json();
}

export async function deleteWebAuthnCredential(credentialId) {
  const response = await fetch(`/api/auth/webauthn/credentials/${credentialId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to remove passkey');
  return response.json();
}

export async function setMfaPreference(method) {
  const response = await fetch('/api/auth/mfa-preference', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ method })
  });
  await ensureResponseOk(response, 'Failed to save MFA preference');
  return response.json();
}

// ── Session Recordings ───────────────────────────────────────────────

export async function fetchRecordings(sessionId = null) {
  const params = sessionId ? `?sessionId=${sessionId}` : '';
  const response = await fetch(`/api/recordings${params}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch recordings');
  return response.json();
}

export async function fetchRecordingCast(recordingId) {
  const response = await fetch(`/api/recordings/${recordingId}/cast`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch recording data');
  return response.text();
}

// ── Dashboard Stats ──────────────────────────────────────────────────

export async function fetchStats() {
  const response = await fetch('/api/stats', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch stats');
  return response.json();
}

// ── Resource Credentials (Vault) ─────────────────────────────────────

export async function fetchResourceCredentials(resourceId) {
  const response = await fetch(`/api/resources/${resourceId}/credentials`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch credentials');
  return response.json();
}

export async function issueEphemeralCredential(resourceId) {
  const response = await fetch(`/api/resources/${resourceId}/ephemeral-credentials`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to issue ephemeral credential lease');
  return response.json();
}

export async function consumeEphemeralCredential(leaseId) {
  const response = await fetch(`/api/ephemeral-credentials/${leaseId}/consume`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to consume ephemeral credential lease');
  return response.json();
}

// ── Access Requests (Dual Control) ────────────────────────────────────

export async function fetchAccessRequests() {
  const response = await fetch('/api/access-requests', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch access requests');
  return response.json();
}

export async function createAccessRequest(payload) {
  const response = await fetch('/api/access-requests', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload)
  });
  await ensureResponseOk(response, 'Failed to create access request');
  return response.json();
}

export async function approveAccessRequest(requestId) {
  const response = await fetch(`/api/access-requests/${requestId}/approve`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to approve access request');
  return response.json();
}

export async function denyAccessRequest(requestId) {
  const response = await fetch(`/api/access-requests/${requestId}/deny`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to deny access request');
  return response.json();
}

// ── Relay Control Plane ───────────────────────────────────────────────

export async function fetchRelays() {
  const response = await fetch('/api/relays', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch relays');
  return response.json();
}

export async function fetchRelayConfig() {
  const response = await fetch('/api/relays/config', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch relay config');
  return response.json();
}

export async function createRelayEnrollmentToken(payload = {}) {
  const response = await fetch('/api/relays/enrollment-token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to create relay enrollment token');
  return response.json();
}

export async function createRelayCertificate(payload = {}) {
  const response = await fetch('/api/relays/certificate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to create relay certificate');
  return response.json();
}

export async function assignRelayToResource(resourceId, relayId) {
  const response = await fetch('/api/relays/assign', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ resourceId, relayId })
  });
  await ensureResponseOk(response, 'Failed to assign relay');
  return response.json();
}

export async function clearRelayForResource(resourceId) {
  const response = await fetch('/api/relays/assign', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ resourceId })
  });
  await ensureResponseOk(response, 'Failed to clear relay assignment');
  return response.json();
}

export async function fetchRelayResolution(resourceId) {
  const response = await fetch(`/api/relays/resolve/${resourceId}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to resolve relay route');
  return response.json();
}

// ── Enterprise Foundations ───────────────────────────────────────────

export function startOidcSso(options = {}) {
  if (typeof window === 'undefined') {
    return;
  }
  const params = new URLSearchParams();
  if (options.provider) {
    params.set('provider', String(options.provider));
  }
  if (options.postLoginRedirect) {
    params.set('postLoginRedirect', String(options.postLoginRedirect));
  }
  const query = params.toString();
  window.location.assign(`/api/auth/sso/oidc/start${query ? `?${query}` : ''}`);
}

export async function fetchSsoProviders() {
  const response = await fetch('/api/auth/sso/providers', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SSO providers');
  return response.json();
}

export async function fetchSsoConfig() {
  const response = await fetch('/api/auth/sso/config', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SSO config');
  return response.json();
}

export async function fetchDirectoryProviders() {
  const response = await fetch('/api/auth/directory/providers', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch directory providers');
  return response.json();
}

export async function fetchLdapConfig() {
  const response = await fetch('/api/auth/directory/ldap/config', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch LDAP config');
  return response.json();
}

export async function testLdapBind(payload) {
  const response = await fetch('/api/auth/directory/ldap/test-bind', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to test LDAP bind');
  return response.json();
}

export async function fetchScimServiceProviderConfig() {
  const response = await fetch('/api/scim/v2/ServiceProviderConfig', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SCIM service provider config');
  return response.json();
}

function buildScimListQuery(params = {}) {
  const query = new URLSearchParams();
  if (typeof params.startIndex === 'number' && Number.isFinite(params.startIndex)) {
    query.set('startIndex', String(Math.trunc(params.startIndex)));
  }
  if (typeof params.count === 'number' && Number.isFinite(params.count)) {
    query.set('count', String(Math.trunc(params.count)));
  }
  if (params.filter) {
    query.set('filter', String(params.filter));
  }
  const queryString = query.toString();
  return queryString ? `?${queryString}` : '';
}

export async function fetchScimUsers(params = {}) {
  const response = await fetch(`/api/scim/v2/Users${buildScimListQuery(params)}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SCIM users');
  return response.json();
}

export async function fetchScimUser(userIdOrName) {
  const response = await fetch(`/api/scim/v2/Users/${encodeURIComponent(String(userIdOrName))}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SCIM user');
  return response.json();
}

export async function createScimUser(payload) {
  const response = await fetch('/api/scim/v2/Users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to create SCIM user');
  return response.json();
}

export async function updateScimUser(userIdOrName, payload) {
  const response = await fetch(`/api/scim/v2/Users/${encodeURIComponent(String(userIdOrName))}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to update SCIM user');
  return response.json();
}

export async function patchScimUser(userIdOrName, operations) {
  const response = await fetch(`/api/scim/v2/Users/${encodeURIComponent(String(userIdOrName))}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: Array.isArray(operations) ? operations : []
    })
  });
  await ensureResponseOk(response, 'Failed to patch SCIM user');
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export async function deleteScimUser(userIdOrName) {
  const response = await fetch(`/api/scim/v2/Users/${encodeURIComponent(String(userIdOrName))}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to delete SCIM user');
}

export async function fetchScimGroups(params = {}) {
  const response = await fetch(`/api/scim/v2/Groups${buildScimListQuery(params)}`, {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SCIM groups');
  return response.json();
}

export async function fetchItsmProviders() {
  const response = await fetch('/api/integrations/itsm/providers', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch ITSM providers');
  return response.json();
}

export async function verifyItsmTicket(payload) {
  const response = await fetch('/api/integrations/itsm/verify-ticket', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to verify ITSM ticket');
  return response.json();
}

export async function fetchSiemChannels() {
  const response = await fetch('/api/integrations/siem/channels', {
    headers: withAuthHeaders()
  });
  await ensureResponseOk(response, 'Failed to fetch SIEM channels');
  return response.json();
}

export async function forwardSiemEvent(payload) {
  const response = await fetch('/api/integrations/siem/events', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify(payload || {})
  });
  await ensureResponseOk(response, 'Failed to forward SIEM event');
  return response.json();
}

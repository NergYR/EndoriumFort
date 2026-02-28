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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Logout failed');
  }
  return response.json();
}

export async function changePassword(currentPassword, newPassword) {
  const response = await fetch('/api/auth/change-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...withAuthHeaders()
    },
    body: JSON.stringify({ currentPassword, newPassword })
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to change password');
  }
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
  if (!response.ok) {
    throw new Error('Failed to fetch sessions');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to create session');
  }
  return response.json();
}

export async function terminateSession(sessionId) {
  const response = await fetch(`/api/sessions/${sessionId}/terminate`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to terminate session');
  }
  return response.json();
}

export async function fetchAudit() {
  const response = await fetch('/api/audit', {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch audit log');
  }
  return response.json();
}

export async function fetchResources() {
  const response = await fetch('/api/resources', {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch resources');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to create resource');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to update resource');
  }
  return response.json();
}

export async function deleteResource(resourceId) {
  const response = await fetch(`/api/resources/${resourceId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to delete resource');
  }
  return response.json();
}

export async function fetchUsers() {
  const response = await fetch('/api/users', {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch users');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to create user');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to update user');
  }
  return response.json();
}

export async function deleteUser(userId) {
  const response = await fetch(`/api/users/${userId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to delete user');
  }
  return response.json();
}

export async function getUserResourcePermissions(userId) {
  const response = await fetch(`/api/users/${userId}/resources`, {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    throw new Error('Failed to fetch permissions');
  }
  return response.json();
}

export async function grantResourcePermission(userId, resourceId) {
  const response = await fetch(`/api/users/${userId}/resources/${resourceId}`, {
    method: 'POST',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to grant permission');
  }
  return response.json();
}

export async function revokeResourcePermission(userId, resourceId) {
  const response = await fetch(`/api/users/${userId}/resources/${resourceId}`, {
    method: 'DELETE',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to revoke permission');
  }
  return response.json();
}

// ── 2FA / TOTP ───────────────────────────────────────────────────────

export async function setup2FA() {
  const response = await fetch('/api/auth/setup-2fa', {
    method: 'POST',
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to setup 2FA');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to verify 2FA');
  }
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
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to disable 2FA');
  }
  return response.json();
}

export async function get2FAStatus() {
  const response = await fetch('/api/auth/2fa-status', {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    throw new Error('Failed to fetch 2FA status');
  }
  return response.json();
}

// ── Session Recordings ───────────────────────────────────────────────

export async function fetchRecordings(sessionId = null) {
  const params = sessionId ? `?sessionId=${sessionId}` : '';
  const response = await fetch(`/api/recordings${params}`, {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch recordings');
  }
  return response.json();
}

export async function fetchRecordingCast(recordingId) {
  const response = await fetch(`/api/recordings/${recordingId}/cast`, {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch recording data');
  }
  return response.text();
}

// ── Dashboard Stats ──────────────────────────────────────────────────

export async function fetchStats() {
  const response = await fetch('/api/stats', {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    throw new Error('Failed to fetch stats');
  }
  return response.json();
}

// ── Resource Credentials (Vault) ─────────────────────────────────────

export async function fetchResourceCredentials(resourceId) {
  const response = await fetch(`/api/resources/${resourceId}/credentials`, {
    headers: withAuthHeaders()
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'Failed to fetch credentials');
  }
  return response.json();
}

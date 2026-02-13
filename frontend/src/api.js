let authToken = '';

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

export const normalizeRiskLevel = (value) => {
  const normalized = String(value || 'low').toLowerCase();
  return ['low', 'medium', 'high', 'critical'].includes(normalized)
    ? normalized
    : 'low';
};

const fallbackTranslate = (key, params = {}) => {
  const dictionary = {
    'policy.risk': `Risk ${params.level}`,
    'policy.reasonRequired': 'Reason required',
    'policy.dualApproval': 'Dual approval',
    'policy.adaptiveControls': 'Adaptive controls',
    'policy.sshGuard': 'SSH guard',
    'policy.tunnelLimit': `Tunnel limit ${params.limit}/min`,
    'policy.mfaSensitive': 'MFA-sensitive',
    'policy.requestApproval': 'Request approval',
    'policy.connectNow': 'Connect now',
    'policy.ticketOrPurposeLikely': 'Ticket or purpose likely',
    'policy.purposeRequired': 'Purpose required'
  };
  return dictionary[key] || key;
};

export const describeResourcePolicy = (resource, translate = fallbackTranslate) => {
  const riskLevel = normalizeRiskLevel(resource?.riskLevel);
  const items = [translate('policy.risk', { level: riskLevel })];
  const tunnelLimit = Math.max(0, Number(resource?.tunnelTicketRateLimitMaxAttempts) || 0);
  const protocol = String(resource?.protocol || '').toLowerCase();
  if (resource?.requireAccessJustification) items.push(translate('policy.reasonRequired'));
  if (resource?.requireDualApproval) items.push(translate('policy.dualApproval'));
  if (resource?.adaptiveAccessPolicy) items.push(translate('policy.adaptiveControls'));
  if (resource?.enableCommandGuard) items.push(translate('policy.sshGuard'));
  if (['agent', 'rdp', 'vnc'].includes(protocol) && tunnelLimit > 0) {
    items.push(translate('policy.tunnelLimit', { limit: tunnelLimit }));
  }
  if (riskLevel === 'high' || riskLevel === 'critical') items.push(translate('policy.mfaSensitive'));
  return items;
};

export const describeAccessOutcome = (resource, translate = fallbackTranslate) => {
  const riskLevel = normalizeRiskLevel(resource?.riskLevel);
  const checks = [];
  if (resource?.requireDualApproval) {
    checks.push(translate('policy.requestApproval'));
  } else {
    checks.push(translate('policy.connectNow'));
  }
  if (resource?.requireAccessJustification) checks.push(translate('policy.reasonRequired'));
  if (resource?.adaptiveAccessPolicy && (riskLevel === 'high' || riskLevel === 'critical')) {
    checks.push(translate('policy.ticketOrPurposeLikely'));
  } else if (riskLevel === 'high' || riskLevel === 'critical') {
    checks.push(translate('policy.purposeRequired'));
  }
  return checks;
};

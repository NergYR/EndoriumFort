export const normalizeRiskLevel = (value) => {
  const normalized = String(value || 'low').toLowerCase();
  return ['low', 'medium', 'high', 'critical'].includes(normalized)
    ? normalized
    : 'low';
};

export const describeResourcePolicy = (resource) => {
  const riskLevel = normalizeRiskLevel(resource?.riskLevel);
  const items = [`Risk ${riskLevel}`];
  if (resource?.requireAccessJustification) items.push('Reason required');
  if (resource?.requireDualApproval) items.push('Dual approval');
  if (resource?.adaptiveAccessPolicy) items.push('Adaptive controls');
  if (resource?.enableCommandGuard) items.push('SSH guard');
  if (riskLevel === 'high' || riskLevel === 'critical') items.push('MFA-sensitive');
  return items;
};

export const describeAccessOutcome = (resource) => {
  const riskLevel = normalizeRiskLevel(resource?.riskLevel);
  const checks = [];
  if (resource?.requireDualApproval) {
    checks.push('Request approval');
  } else {
    checks.push('Connect now');
  }
  if (resource?.requireAccessJustification) checks.push('Reason required');
  if (resource?.adaptiveAccessPolicy && (riskLevel === 'high' || riskLevel === 'critical')) {
    checks.push('Ticket or purpose likely');
  } else if (riskLevel === 'high' || riskLevel === 'critical') {
    checks.push('Purpose required');
  }
  return checks;
};

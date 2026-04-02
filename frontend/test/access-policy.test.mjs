import test from 'node:test';
import assert from 'node:assert/strict';

import { describeAccessOutcome, describeResourcePolicy, normalizeRiskLevel } from '../src/accessPolicy.js';

test('normalizeRiskLevel falls back to low for unknown values', () => {
  assert.equal(normalizeRiskLevel('CRITICAL'), 'critical');
  assert.equal(normalizeRiskLevel('weird'), 'low');
  assert.equal(normalizeRiskLevel(''), 'low');
});

test('describeResourcePolicy summarizes enabled controls', () => {
  const items = describeResourcePolicy({
    riskLevel: 'high',
    requireAccessJustification: true,
    requireDualApproval: true,
    adaptiveAccessPolicy: true,
    enableCommandGuard: false
  });

  assert.deepEqual(items, [
    'Risk high',
    'Reason required',
    'Dual approval',
    'Adaptive controls',
    'MFA-sensitive'
  ]);
});

test('describeAccessOutcome explains next steps before connect', () => {
  const items = describeAccessOutcome({
    riskLevel: 'critical',
    requireAccessJustification: true,
    requireDualApproval: false,
    adaptiveAccessPolicy: true
  });

  assert.deepEqual(items, [
    'Connect now',
    'Reason required',
    'Ticket or purpose likely'
  ]);
});

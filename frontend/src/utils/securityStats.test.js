import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getAiRiskTier,
  getAiRiskExplanation,
  getAiRiskExplanationStyle
} from './securityStats.js';

test('AI Risk Explanation - Real-world Gmail SMTP case (CRITICAL ML + SECURE Posture + 0 Findings)', () => {
  const aiRisk = {
    score: 97.2,
    operational_risk_tier: 'CRITICAL',
    confidence: 0.98,
    top_risk_factors: []
  };
  const postureStatus = 'SECURE';
  const findingsCount = 0;

  const explanation = getAiRiskExplanation(aiRisk, postureStatus, findingsCount);
  assert.equal(
    explanation,
    'AI predicted critical risk, but no deterministic security findings were observed. AI risk is a secondary signal and does not override the deterministic security posture.'
  );

  const style = getAiRiskExplanationStyle(aiRisk, postureStatus, findingsCount);
  assert.equal(style.icon, 'info');
  assert.match(style.containerClass, /border-sky/);
});

test('AI Risk Explanation - Reconciled HIGH case (HIGH ML + SECURE Posture + 0 Findings)', () => {
  const explanation = getAiRiskExplanation(68.5, 'SECURE', 0);
  assert.equal(
    explanation,
    'AI predicted elevated risk, but no deterministic security findings were observed. AI risk is a secondary signal and does not override the deterministic security posture.'
  );

  const style = getAiRiskExplanationStyle(68.5, 'SECURE', 0);
  assert.equal(style.icon, 'info');
});

test('AI Risk Explanation - Confirmed CRITICAL case with deterministic findings', () => {
  const findings = [{ id: 'f1', isFail: true, severity: 'CRITICAL', title: 'Plaintext credentials' }];
  const explanation = getAiRiskExplanation({ score: 95.0 }, 'AT_RISK', findings);
  assert.equal(
    explanation,
    'AI indicates critical AI-predicted risk. Review contributing factors and correlate with deterministic security findings.'
  );

  const style = getAiRiskExplanationStyle({ score: 95.0 }, 'AT_RISK', findings);
  assert.equal(style.icon, 'warning');
  assert.match(style.containerClass, /border-rose/);
});

test('AI Risk Explanation - Confirmed HIGH case with deterministic findings', () => {
  const explanation = getAiRiskExplanation(75.0, 'AT_RISK', 1);
  assert.equal(
    explanation,
    'AI indicates elevated cryptographic risk. Review contributing factors.'
  );

  const style = getAiRiskExplanationStyle(75.0, 'AT_RISK', 1);
  assert.equal(style.icon, 'warning');
  assert.match(style.containerClass, /border-rose/);
});

test('AI Risk Explanation - MODERATE risk tier', () => {
  const explanation = getAiRiskExplanation(35.0, 'SECURE', 0);
  assert.equal(
    explanation,
    'AI indicates moderate cryptographic risk. Review contributing factors.'
  );

  const style = getAiRiskExplanationStyle(35.0, 'SECURE', 0);
  assert.equal(style.icon, 'warning');
  assert.match(style.containerClass, /border-amber/);
});

test('AI Risk Explanation - LOW risk tier', () => {
  const explanation = getAiRiskExplanation(12.0, 'SECURE', 0);
  assert.equal(
    explanation,
    'AI indicates low cryptographic risk.'
  );

  const style = getAiRiskExplanationStyle(12.0, 'SECURE', 0);
  assert.equal(style.icon, 'verified');
  assert.match(style.containerClass, /border-emerald/);
});

test('AI Risk Explanation - Null safety & older records', () => {
  assert.equal(getAiRiskExplanation(null), 'AI indicates low cryptographic risk.');
  assert.equal(getAiRiskExplanation(undefined), 'AI indicates low cryptographic risk.');
  assert.equal(getAiRiskExplanation({}), 'AI indicates low cryptographic risk.');
  assert.equal(getAiRiskExplanation({ score: null }), 'AI indicates low cryptographic risk.');

  const style = getAiRiskExplanationStyle(null);
  assert.equal(style.icon, 'verified');
});

test('AI Risk Tier Derivation', () => {
  assert.equal(getAiRiskTier(0), 'LOW');
  assert.equal(getAiRiskTier(20.0), 'LOW');
  assert.equal(getAiRiskTier(20.1), 'MODERATE');
  assert.equal(getAiRiskTier(50.0), 'MODERATE');
  assert.equal(getAiRiskTier(50.1), 'HIGH');
  assert.equal(getAiRiskTier(80.0), 'HIGH');
  assert.equal(getAiRiskTier(80.1), 'CRITICAL');
  assert.equal(getAiRiskTier(100), 'CRITICAL');
});

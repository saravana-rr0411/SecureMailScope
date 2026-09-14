import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ROLES,
  ROUTES,
  normalizePath,
  isProtectedRoute,
  evaluateRouteAccess,
  getDefaultRouteForRole,
  getNavItemsForRole,
  validateLoginRoleMatch,
  canRoleAccessRoute,
} from './authRbac.js';

test('1. Unauthenticated users cannot access protected routes and are redirected to /login', () => {
  // Test root
  assert.deepEqual(evaluateRouteAccess('/', null), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  // Test /overview
  assert.deepEqual(evaluateRouteAccess('/overview', null), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  // Test /forensics
  assert.deepEqual(evaluateRouteAccess('/forensics', null), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  // Test /executive-dashboard
  assert.deepEqual(evaluateRouteAccess('/executive-dashboard', null), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  // Test arbitrary route
  assert.deepEqual(evaluateRouteAccess('/admin/settings', null), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  // /login is allowed for unauthenticated
  assert.deepEqual(evaluateRouteAccess('/login', null), {
    allowed: true,
    redirectPath: null,
  });
});

test('2. SOC_ANALYST default route is /overview', () => {
  assert.equal(getDefaultRouteForRole(ROLES.SOC_ANALYST), ROUTES.OVERVIEW);
  // Navigating to /login redirects to /overview
  assert.deepEqual(evaluateRouteAccess('/login', ROLES.SOC_ANALYST), {
    allowed: false,
    redirectPath: ROUTES.OVERVIEW,
  });
  // /overview is allowed
  assert.deepEqual(evaluateRouteAccess('/overview', ROLES.SOC_ANALYST), {
    allowed: true,
    redirectPath: null,
  });
});

test('3. SOC_ANALYST -> /forensics is allowed', () => {
  assert.deepEqual(evaluateRouteAccess('/forensics', ROLES.SOC_ANALYST), {
    allowed: true,
    redirectPath: null,
  });
});

test('4. SOC_ANALYST -> /executive-dashboard is denied and redirects to /overview', () => {
  assert.deepEqual(evaluateRouteAccess('/executive-dashboard', ROLES.SOC_ANALYST), {
    allowed: false,
    redirectPath: ROUTES.OVERVIEW,
  });
});

test('5. EXECUTIVE default route is /executive-dashboard', () => {
  assert.equal(getDefaultRouteForRole(ROLES.EXECUTIVE), ROUTES.EXECUTIVE);
  // /executive-dashboard is allowed
  assert.deepEqual(evaluateRouteAccess('/executive-dashboard', ROLES.EXECUTIVE), {
    allowed: true,
    redirectPath: null,
  });
  // Navigating to /login redirects to /executive-dashboard
  assert.deepEqual(evaluateRouteAccess('/login', ROLES.EXECUTIVE), {
    allowed: false,
    redirectPath: ROUTES.EXECUTIVE,
  });
});

test('6. EXECUTIVE -> /overview is denied and redirects to /executive-dashboard', () => {
  assert.deepEqual(evaluateRouteAccess('/overview', ROLES.EXECUTIVE), {
    allowed: false,
    redirectPath: ROUTES.EXECUTIVE,
  });
});

test('7. EXECUTIVE -> /forensics is denied and redirects to /executive-dashboard', () => {
  assert.deepEqual(evaluateRouteAccess('/forensics', ROLES.EXECUTIVE), {
    allowed: false,
    redirectPath: ROUTES.EXECUTIVE,
  });
});

test('8. Navigation items are strictly scoped by role', () => {
  const socNav = getNavItemsForRole(ROLES.SOC_ANALYST);
  assert.equal(socNav.length, 2);
  assert.ok(socNav.some((item) => item.path === ROUTES.OVERVIEW));
  assert.ok(socNav.some((item) => item.path === ROUTES.FORENSICS));
  assert.ok(!socNav.some((item) => item.path === ROUTES.EXECUTIVE));

  const execNav = getNavItemsForRole(ROLES.EXECUTIVE);
  assert.equal(execNav.length, 1);
  assert.ok(execNav.some((item) => item.path === ROUTES.EXECUTIVE));
  assert.ok(!execNav.some((item) => item.path === ROUTES.OVERVIEW));
  assert.ok(!execNav.some((item) => item.path === ROUTES.FORENSICS));
});

test('9. Unassigned role or arbitrary user cannot access any protected route', () => {
  assert.deepEqual(evaluateRouteAccess('/overview', 'SOME_UNASSIGNED_ROLE'), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
  assert.deepEqual(evaluateRouteAccess('/executive-dashboard', undefined), {
    allowed: false,
    redirectPath: ROUTES.LOGIN,
  });
});

test('10. Path normalization handles trailing slashes and aliases', () => {
  assert.equal(normalizePath('/overview/'), ROUTES.OVERVIEW);
  assert.equal(normalizePath('/forensics/'), ROUTES.FORENSICS);
  assert.equal(normalizePath('/executive-dashboard/'), ROUTES.EXECUTIVE);
  assert.equal(normalizePath('/executive'), ROUTES.EXECUTIVE);
  assert.equal(normalizePath('/'), '/');
  assert.equal(normalizePath(''), '/');
});

test('11. isProtectedRoute correctly identifies protected routes', () => {
  assert.equal(isProtectedRoute('/login'), false);
  assert.equal(isProtectedRoute('/overview'), true);
  assert.equal(isProtectedRoute('/forensics'), true);
  assert.equal(isProtectedRoute('/executive-dashboard'), true);
});

test('12. Database role is strictly authoritative over client UI selection', () => {
  // Simulating a user who selected 'EXECUTIVE' in the login dropdown,
  // but their authoritative database role is 'SOC_ANALYST'
  const visualSelection = ROLES.EXECUTIVE;
  const authoritativeDbRole = ROLES.SOC_ANALYST;
  assert.notEqual(visualSelection, authoritativeDbRole);

  // The route evaluation MUST use the authoritative database role
  const access = evaluateRouteAccess('/executive-dashboard', authoritativeDbRole);
  assert.deepEqual(access, {
    allowed: false,
    redirectPath: ROUTES.OVERVIEW,
  });

  // Even if visualSelection was EXECUTIVE, home route is strictly SOC_ANALYST's /overview
  assert.equal(getDefaultRouteForRole(authoritativeDbRole), ROUTES.OVERVIEW);
});

test('13. validateLoginRoleMatch strictly rejects unassigned accounts and role mismatches', () => {
  // Unassigned user account
  const unassignedResult = validateLoginRoleMatch(ROLES.SOC_ANALYST, null);
  assert.equal(unassignedResult.success, false);
  assert.equal(unassignedResult.role, null);
  assert.equal(unassignedResult.error, 'Access denied.');

  // User selects EXECUTIVE on UI, but database role is SOC_ANALYST
  const mismatchSoc = validateLoginRoleMatch(ROLES.EXECUTIVE, ROLES.SOC_ANALYST);
  assert.equal(mismatchSoc.success, false);
  assert.equal(mismatchSoc.role, null);
  assert.equal(mismatchSoc.error, 'Access denied.');

  // User selects SOC_ANALYST on UI, but database role is EXECUTIVE
  const mismatchExec = validateLoginRoleMatch(ROLES.SOC_ANALYST, ROLES.EXECUTIVE);
  assert.equal(mismatchExec.success, false);
  assert.equal(mismatchExec.role, null);
  assert.equal(mismatchExec.error, 'Access denied.');
});

test('14. validateLoginRoleMatch grants access only when selected role matches database role', () => {
  // Valid SOC Analyst login
  const validSoc = validateLoginRoleMatch(ROLES.SOC_ANALYST, ROLES.SOC_ANALYST);
  assert.equal(validSoc.success, true);
  assert.equal(validSoc.role, ROLES.SOC_ANALYST);
  assert.equal(validSoc.error, null);

  // Valid Executive login
  const validExec = validateLoginRoleMatch(ROLES.EXECUTIVE, ROLES.EXECUTIVE);
  assert.equal(validExec.success, true);
  assert.equal(validExec.role, ROLES.EXECUTIVE);
  assert.equal(validExec.error, null);
});

test('15. Proof that a SOC_ANALYST cannot enter any Executive pages', () => {
  const socRole = ROLES.SOC_ANALYST;

  // Executive Dashboard is denied
  const execDashAccess = evaluateRouteAccess('/executive-dashboard', socRole);
  assert.equal(execDashAccess.allowed, false);
  assert.equal(execDashAccess.redirectPath, ROUTES.OVERVIEW);
  assert.equal(canRoleAccessRoute(socRole, '/executive-dashboard'), false);

  // Executive alias is denied
  const execAliasAccess = evaluateRouteAccess('/executive', socRole);
  assert.equal(execAliasAccess.allowed, false);
  assert.equal(execAliasAccess.redirectPath, ROUTES.OVERVIEW);
  assert.equal(canRoleAccessRoute(socRole, '/executive'), false);

  // SOC Analyst allowed pages
  assert.equal(canRoleAccessRoute(socRole, '/overview'), true);
  assert.equal(canRoleAccessRoute(socRole, '/forensics'), true);
  assert.equal(canRoleAccessRoute(socRole, '/sessions'), true);
  assert.equal(canRoleAccessRoute(socRole, '/ai_risk'), true);
});

test('16. Proof that an EXECUTIVE cannot enter any SOC Analyst pages', () => {
  const execRole = ROLES.EXECUTIVE;

  // Overview is denied
  const overviewAccess = evaluateRouteAccess('/overview', execRole);
  assert.equal(overviewAccess.allowed, false);
  assert.equal(overviewAccess.redirectPath, ROUTES.EXECUTIVE);
  assert.equal(canRoleAccessRoute(execRole, '/overview'), false);

  // Forensics is denied
  const forensicsAccess = evaluateRouteAccess('/forensics', execRole);
  assert.equal(forensicsAccess.allowed, false);
  assert.equal(forensicsAccess.redirectPath, ROUTES.EXECUTIVE);
  assert.equal(canRoleAccessRoute(execRole, '/forensics'), false);

  // Sessions is denied
  const sessionsAccess = evaluateRouteAccess('/sessions', execRole);
  assert.equal(sessionsAccess.allowed, false);
  assert.equal(sessionsAccess.redirectPath, ROUTES.EXECUTIVE);
  assert.equal(canRoleAccessRoute(execRole, '/sessions'), false);

  // AI Risk is denied
  const aiRiskAccess = evaluateRouteAccess('/ai_risk', execRole);
  assert.equal(aiRiskAccess.allowed, false);
  assert.equal(aiRiskAccess.redirectPath, ROUTES.EXECUTIVE);
  assert.equal(canRoleAccessRoute(execRole, '/ai_risk'), false);

  // Executive allowed pages
  assert.equal(canRoleAccessRoute(execRole, '/executive-dashboard'), true);
  assert.equal(canRoleAccessRoute(execRole, '/executive'), true);
});

test('17. Role selector button NEVER determines authorization or grants cross-role access', () => {
  // Scenario: An attacker with SOC_ANALYST credentials toggles the UI selector to 'EXECUTIVE'
  const userDatabaseRole = ROLES.SOC_ANALYST;
  const toggledButtonContext = ROLES.EXECUTIVE;

  // 1. Login attempt MUST fail because the button does not match the database role
  const loginValidation = validateLoginRoleMatch(toggledButtonContext, userDatabaseRole);
  assert.equal(loginValidation.success, false);
  assert.match(loginValidation.error, /Access denied/i);

  // 2. Even if the attacker attempts to use the button selection for authorization,
  // evaluateRouteAccess strictly takes the database role and forbids executive access
  const executiveRouteAccess = evaluateRouteAccess(ROUTES.EXECUTIVE, userDatabaseRole);
  assert.equal(executiveRouteAccess.allowed, false);
  assert.equal(executiveRouteAccess.redirectPath, ROUTES.OVERVIEW);

  // 3. The reverse scenario: Executive toggling to SOC Analyst
  const execDatabaseRole = ROLES.EXECUTIVE;
  const toggledAnalystButton = ROLES.SOC_ANALYST;

  const execLoginValidation = validateLoginRoleMatch(toggledAnalystButton, execDatabaseRole);
  assert.equal(execLoginValidation.success, false);
  assert.match(execLoginValidation.error, /Access denied/i);

  const analystRouteAccess = evaluateRouteAccess(ROUTES.OVERVIEW, execDatabaseRole);
  assert.equal(analystRouteAccess.allowed, false);
  assert.equal(analystRouteAccess.redirectPath, ROUTES.EXECUTIVE);
});


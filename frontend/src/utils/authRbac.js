export const ROLES = {
  SOC_ANALYST: 'SOC_ANALYST',
  EXECUTIVE: 'EXECUTIVE',
};

export const ROUTES = {
  LOGIN: '/login',
  OVERVIEW: '/overview',
  FORENSICS: '/forensics',
  EXECUTIVE: '/executive-dashboard',
};

/**
 * Normalizes a pathname string to a canonical route.
 */
export function normalizePath(pathname) {
  if (!pathname || pathname === '') {
    return '/';
  }
  const clean = pathname.toLowerCase().replace(/\/+$/, '');
  if (clean === '/overview') return ROUTES.OVERVIEW;
  if (clean === '/forensics' || clean === '/sessions' || clean === '/ai_risk') return ROUTES.FORENSICS;
  if (clean === '/executive-dashboard' || clean === '/executive') return ROUTES.EXECUTIVE;
  if (clean === '/login') return ROUTES.LOGIN;
  return clean || '/';
}

/**
 * Checks if a route requires authentication.
 */
export function isProtectedRoute(pathname) {
  const norm = normalizePath(pathname);
  return norm !== ROUTES.LOGIN;
}

/**
 * Evaluates route access based on current path and authoritative database user role.
 *
 * Matrix:
 * - Unauthenticated: Any protected route (or '/') -> /login
 * - SOC_ANALYST: /overview (allowed), /forensics (allowed), /executive-dashboard (denied -> /overview)
 * - EXECUTIVE: /executive-dashboard (allowed), /overview (denied -> /executive-dashboard), /forensics (denied -> /executive-dashboard)
 *
 * @param {string} pathname
 * @param {string|null} userRole
 * @returns {{ allowed: boolean, redirectPath: string | null }}
 */
export function evaluateRouteAccess(pathname, userRole) {
  const norm = normalizePath(pathname);

  // Unauthenticated state
  if (!userRole) {
    if (norm === ROUTES.LOGIN) {
      return { allowed: true, redirectPath: null };
    }
    return { allowed: false, redirectPath: ROUTES.LOGIN };
  }

  // SOC Analyst access evaluation
  if (userRole === ROLES.SOC_ANALYST) {
    if (norm === ROUTES.OVERVIEW || norm === ROUTES.FORENSICS) {
      return { allowed: true, redirectPath: null };
    }
    // Access to executive dashboard, login, root, or other route redirects to /overview
    return { allowed: false, redirectPath: ROUTES.OVERVIEW };
  }

  // Executive access evaluation
  if (userRole === ROLES.EXECUTIVE) {
    if (norm === ROUTES.EXECUTIVE) {
      return { allowed: true, redirectPath: null };
    }
    // Access to overview, forensics, login, root, or other route redirects to /executive-dashboard
    return { allowed: false, redirectPath: ROUTES.EXECUTIVE };
  }

  // Fallback: unassigned or invalid role is denied access to all protected screens
  return { allowed: false, redirectPath: ROUTES.LOGIN };
}

/**
 * Returns the default home route for a given authoritative role.
 */
export function getDefaultRouteForRole(role) {
  if (role === ROLES.SOC_ANALYST) return ROUTES.OVERVIEW;
  if (role === ROLES.EXECUTIVE) return ROUTES.EXECUTIVE;
  return ROUTES.LOGIN;
}

/**
 * Returns allowed navigation items strictly mapped to the assigned role.
 */
export function getNavItemsForRole(role) {
  if (role === ROLES.SOC_ANALYST) {
    return [
      { id: 'overview', label: 'Overview', path: ROUTES.OVERVIEW, icon: 'analytics' },
      { id: 'forensics', label: 'Forensics & AI Risk', path: ROUTES.FORENSICS, icon: 'manage_search' },
    ];
  }
  if (role === ROLES.EXECUTIVE) {
    return [
      { id: 'executive', label: 'Executive Dashboard', path: ROUTES.EXECUTIVE, icon: 'shield' },
    ];
  }
  return [];
}

/**
 * Strictly verifies whether the user's selected login workstation role matches
 * their authoritative database role retrieved from public.user_roles.
 *
 * Requirements:
 * - The selected role button must NEVER determine or elevate authorization.
 * - If the user has no assigned database role, access is denied.
 * - If the selected role does not match the authoritative database role, access is denied.
 * - Only if the selected role matches the database role is access granted.
 *
 * @param {string} selectedRole - The role button selected by user on the login screen
 * @param {string|null} databaseRole - The authoritative role from public.user_roles
 * @returns {{ success: boolean, role: string|null, error: string|null }}
 */
export function validateLoginRoleMatch(selectedRole, databaseRole) {
  if (!databaseRole || selectedRole !== databaseRole) {
    return {
      success: false,
      role: null,
      error: 'Access denied.',
    };
  }

  return {
    success: true,
    role: databaseRole,
    error: null,
  };
}

/**
 * Checks if a specific role is permitted to access a given pathname.
 *
 * @param {string} role
 * @param {string} pathname
 * @returns {boolean}
 */
export function canRoleAccessRoute(role, pathname) {
  const result = evaluateRouteAccess(pathname, role);
  return result.allowed;
}


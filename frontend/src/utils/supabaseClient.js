import { createClient } from '@supabase/supabase-js';

const metaEnv =
  typeof import.meta !== 'undefined' && import.meta.env
    ? import.meta.env
    : typeof process !== 'undefined' && process.env
    ? process.env
    : {};

const supabaseUrl =
  (metaEnv.VITE_SUPABASE_URL && String(metaEnv.VITE_SUPABASE_URL).trim()) || '';
const supabaseAnonKey =
  (metaEnv.VITE_SUPABASE_ANON_KEY && String(metaEnv.VITE_SUPABASE_ANON_KEY).trim()) || '';

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

/**
 * DEMO_AUTH / DEMO_MODE flag:
 * Defaults to true for hackathon/presentation evaluation mode.
 * In DEMO_MODE, any valid-looking email is accepted without pre-registered accounts,
 * email verification, or OTP.
 * Set VITE_DEMO_AUTH=false to enforce strict Supabase Auth with database-enforced roles.
 */
export const DEMO_AUTH =
  typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_DEMO_AUTH !== undefined
    ? import.meta.env.VITE_DEMO_AUTH !== 'false'
    : true;
export const DEMO_MODE = DEMO_AUTH;

export const DEMO_SESSION_KEY = 'sms_demo_session';

function safeBase64Encode(str) {
  if (typeof window !== 'undefined' && typeof window.btoa === 'function') {
    try {
      return window.btoa(unescape(encodeURIComponent(str)));
    } catch {
      return window.btoa(str);
    }
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf-8').toString('base64');
  }
  return btoa(str);
}

/**
 * Creates a compliant demo user object containing the entered email and selected role.
 */
export function createDemoUser(email, role = 'SOC_ANALYST') {
  const trimmed = (email || '').trim();
  const lower = trimmed.toLowerCase();
  const safeIdPart = lower.replace(/[^a-z0-9]/g, '').slice(0, 16) || 'analyst';
  return {
    id: `demo-${safeIdPart}`,
    email: trimmed,
    role,
    app_metadata: { provider: 'demo' },
    user_metadata: { role },
    aud: 'authenticated',
    created_at: new Date().toISOString(),
  };
}

/**
 * Creates a complete demo session containing user profile and token.
 */
export function createDemoSession(email, role = 'SOC_ANALYST') {
  const user = createDemoUser(email, role);
  const payload = safeBase64Encode(JSON.stringify({ id: user.id, email: user.email, role }));
  return {
    access_token: `demo-token:${payload}`,
    token_type: 'bearer',
    user,
    role,
    expires_at: Math.floor(Date.now() / 1000) + 86400 * 7,
  };
}

/**
 * Retrieves stored demo session from localStorage if present.
 */
export function getStoredDemoSession() {
  if (typeof window === 'undefined' || !window.localStorage) return null;
  try {
    const raw = localStorage.getItem(DEMO_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && parsed.user && parsed.user.email) {
      return parsed;
    }
  } catch (err) {
    console.warn('Error reading demo session from localStorage:', err);
  }
  return null;
}

/**
 * Persists the demo session in localStorage.
 */
export function saveDemoSession(session) {
  if (typeof window === 'undefined' || !window.localStorage) return;
  try {
    localStorage.setItem(DEMO_SESSION_KEY, JSON.stringify(session));
  } catch (err) {
    console.warn('Error saving demo session to localStorage:', err);
  }
}

/**
 * Clears demo session from localStorage.
 */
export function clearDemoSession() {
  if (typeof window === 'undefined' || !window.localStorage) return;
  try {
    localStorage.removeItem(DEMO_SESSION_KEY);
  } catch (err) {
    console.warn('Error clearing demo session from localStorage:', err);
  }
}

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
        storage: typeof window !== 'undefined' ? window.localStorage : undefined,
      },
    })
  : null;

/**
 * Authoritatively retrieves the application role for a given user ID from public.user_roles.
 * Returns 'SOC_ANALYST', 'EXECUTIVE', or null if unassigned.
 */
export async function fetchUserRole(userId) {
  if (!supabase || !userId) return null;
  try {
    const { data, error } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', userId)
      .maybeSingle();

    if (error) {
      console.error('Failed to retrieve role from user_roles:', error.message);
      return null;
    }
    return data?.role || null;
  } catch (err) {
    console.error('Unexpected error retrieving user role:', err);
    return null;
  }
}

/**
 * Signs out the current user and clears persistent session data.
 */
export async function signOutUser() {
  clearDemoSession();
  if (!supabase) return;
  try {
    await supabase.auth.signOut();
  } catch (err) {
    console.error('Error signing out:', err);
  }
}

/**
 * Retrieves the authorization headers for backend API requests.
 */
export async function getAuthHeaders() {
  if (DEMO_MODE) {
    const demoSession = getStoredDemoSession();
    if (demoSession?.access_token) {
      return { Authorization: `Bearer ${demoSession.access_token}` };
    }
  }
  if (!supabase) return {};
  try {
    const { data } = await supabase.auth.getSession();
    const token = data?.session?.access_token;
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
  } catch (err) {
    console.warn('Error fetching auth token for headers:', err);
  }
  return {};
}


import { createClient } from '@supabase/supabase-js';

const supabaseUrl =
  (import.meta.env.VITE_SUPABASE_URL && String(import.meta.env.VITE_SUPABASE_URL).trim()) || '';
const supabaseAnonKey =
  (import.meta.env.VITE_SUPABASE_ANON_KEY && String(import.meta.env.VITE_SUPABASE_ANON_KEY).trim()) || '';

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

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
  if (!supabase) return;
  try {
    await supabase.auth.signOut();
  } catch (err) {
    console.error('Error signing out:', err);
  }
}

import React, { useState, useEffect, useRef } from 'react';
import { supabase, isSupabaseConfigured, fetchUserRole } from '../utils/supabaseClient';
import { ROLES, validateLoginRoleMatch } from '../utils/authRbac';

/**
 * Dynamic canvas background providing refined, restrained network-node movement
 * and a subtle fine grid. Automatically pauses when prefers-reduced-motion is active
 * and dynamically reacts to dark/light theme changes.
 */
function NetworkCanvas({ theme }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let animationFrameId;
    let width = (canvas.width = canvas.parentElement?.offsetWidth || window.innerWidth);
    let height = (canvas.height = canvas.parentElement?.offsetHeight || window.innerHeight);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.offsetWidth;
      height = canvas.height = canvas.parentElement.offsetHeight;
    };

    window.addEventListener('resize', handleResize);

    const isDark = theme === 'dark';
    const nodeCount = Math.min(30, Math.max(16, Math.floor(width / 36)));

    const nodes = Array.from({ length: nodeCount }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      radius: Math.random() * 1.5 + 1.2,
    }));

    const maxDistance = 140;

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Subtle fine background grid
      const gridSize = 44;
      ctx.strokeStyle = isDark ? 'rgba(255, 255, 255, 0.025)' : 'rgba(0, 0, 0, 0.035)';
      ctx.lineWidth = 0.5;

      ctx.beginPath();
      for (let x = 0; x < width; x += gridSize) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
      }
      ctx.stroke();

      // 2. Animated network nodes & flowing connection lines
      for (let i = 0; i < nodes.length; i++) {
        const n1 = nodes[i];

        if (!prefersReducedMotion) {
          n1.x += n1.vx;
          n1.y += n1.vy;

          if (n1.x < 0) n1.x = width;
          else if (n1.x > width) n1.x = 0;
          if (n1.y < 0) n1.y = height;
          else if (n1.y > height) n1.y = 0;
        }

        // Draw inter-node connection lines
        for (let j = i + 1; j < nodes.length; j++) {
          const n2 = nodes[j];
          const dx = n1.x - n2.x;
          const dy = n1.y - n2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * (isDark ? 0.16 : 0.12);
            ctx.strokeStyle = isDark
              ? `rgba(56, 189, 248, ${alpha})`
              : `rgba(2, 132, 199, ${alpha})`;
            ctx.lineWidth = 0.75;
            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }

        // Draw node
        ctx.fillStyle = isDark
          ? 'rgba(56, 189, 248, 0.55)'
          : 'rgba(2, 132, 199, 0.55)';
        ctx.beginPath();
        ctx.arc(n1.x, n1.y, n1.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(draw);
      }
    };

    draw();

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [theme]);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none z-0"
      aria-hidden="true"
    />
  );
}

export default function LoginScreen({ onLoginSuccess, theme = 'light', onToggleTheme }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [selectedRoleContext, setSelectedRoleContext] = useState(ROLES.SOC_ANALYST);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      setErrorMessage('Invalid credentials.');
      return;
    }

    if (!isSupabaseConfigured || !supabase) {
      setErrorMessage('Configuration error.');
      return;
    }

    setIsLoading(true);

    try {
      // 1. Authenticate with Supabase Auth
      const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
        email: trimmedEmail,
        password,
      });

      if (authError || !authData?.user) {
        setErrorMessage('Invalid credentials.');
        setIsLoading(false);
        return;
      }

      // 2. Authoritatively retrieve the user's role from public.user_roles using user UUID
      const userId = authData.user.id;
      const assignedRole = await fetchUserRole(userId);

      // 3. Strictly validate role match and authorization
      const validation = validateLoginRoleMatch(selectedRoleContext, assignedRole);
      if (!validation.success) {
        setErrorMessage('Access denied.');
        // Safely sign out unassigned or mismatched user so no session persists
        await supabase.auth.signOut();
        setIsLoading(false);
        return;
      }

      // 4. Complete login with authoritative database role (ignoring role button for authorization)
      onLoginSuccess(authData.user, validation.role);
    } catch (err) {
      console.error('Sign-in error:', err);
      setErrorMessage('Connection error.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex flex-col lg:flex-row bg-[#F8FAFC] dark:bg-[#0B0F17] text-slate-900 dark:text-slate-100 antialiased selection:bg-sky-600 selection:text-white transition-colors duration-200 relative overflow-hidden">
      {/* Left Column: Landscape Brand Identity & Dynamic Network Surface */}
      <div className="w-full lg:w-[55%] bg-slate-100/60 dark:bg-[#080C14] border-b lg:border-b-0 lg:border-r border-slate-200 dark:border-[#1B2232] p-8 sm:p-12 lg:p-16 flex flex-col justify-between relative overflow-hidden select-none min-h-[300px] lg:min-h-screen transition-colors duration-200">
        {/* Dynamic ambient network visualization */}
        <NetworkCanvas theme={theme} />

        {/* Top spacer */}
        <div className="relative z-10"></div>

        {/* Large, Prominent SecureMailScope Brand Identity */}
        <div className="relative z-10 my-auto py-10 max-w-xl">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-[-0.035em] text-slate-900 dark:text-white leading-[1.08] font-sans">
            SecureMailScope
          </h1>
          <p className="mt-3 text-sm lg:text-base font-medium tracking-tight text-slate-500 dark:text-slate-400">
            Network traffic cryptographic security & forensics
          </p>
        </div>

        {/* Bottom subtle anchor */}
        <div className="relative z-10 text-xs font-mono text-slate-400 dark:text-slate-600 tracking-wider">
          v1.4
        </div>
      </div>

      {/* Right Column: Refined Enterprise Authentication Pane */}
      <div className="w-full lg:w-[45%] bg-white dark:bg-[#0D111A] flex flex-col justify-between p-6 sm:p-10 lg:p-16 min-h-[480px] lg:min-h-screen transition-colors duration-200">
        {/* Top bar with Dark / Light Mode Toggle */}
        <div className="flex items-center justify-end w-full">
          {onToggleTheme && (
            <button
              type="button"
              onClick={onToggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              className="inline-flex items-center justify-center w-8 h-8 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080C14] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all duration-150 cursor-pointer shadow-xs"
            >
              <span className="material-symbols-outlined text-[17px]">
                {theme === 'dark' ? 'light_mode' : 'dark_mode'}
              </span>
            </button>
          )}
        </div>

        {/* Compact Form Container */}
        <div className="my-auto max-w-[340px] w-full mx-auto">
          <div className="mb-6">
            <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
              Sign In
            </h2>
          </div>

          {/* Short Error Banner */}
          {errorMessage && (
            <div
              role="alert"
              className="mb-4 px-3.5 py-2.5 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 text-rose-700 dark:text-rose-300 text-xs font-medium flex items-center gap-2 animate-in fade-in duration-150"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0"></span>
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Configuration Error (Only on actual config problem) */}
          {!isSupabaseConfigured && (
            <div
              role="alert"
              className="mb-4 px-3.5 py-2.5 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60 text-amber-800 dark:text-amber-300 text-xs font-medium flex items-center gap-2 animate-in fade-in duration-150"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0"></span>
              <span>Configuration error.</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Dynamic Segmented Control with Smooth Sliding Pill */}
            <div>
              <div
                role="radiogroup"
                aria-label="Workstation role selection"
                className="relative p-1 bg-slate-100 dark:bg-[#080C14] rounded-lg border border-slate-200 dark:border-slate-800 flex items-center transition-colors duration-150"
              >
                {/* Animated active pill */}
                <div
                  className={`absolute top-1 bottom-1 left-1 w-[calc(50%-4px)] rounded-md bg-white dark:bg-[#1A2333] shadow-xs border border-slate-200/90 dark:border-slate-700/80 transition-transform duration-200 ease-out pointer-events-none ${
                    selectedRoleContext === ROLES.SOC_ANALYST
                      ? 'translate-x-0'
                      : 'translate-x-full'
                  }`}
                />
                <button
                  type="button"
                  role="radio"
                  aria-checked={selectedRoleContext === ROLES.SOC_ANALYST}
                  onClick={() => setSelectedRoleContext(ROLES.SOC_ANALYST)}
                  className={`relative z-10 w-1/2 py-1.5 text-xs font-semibold tracking-tight transition-colors duration-150 cursor-pointer text-center ${
                    selectedRoleContext === ROLES.SOC_ANALYST
                      ? 'text-slate-900 dark:text-white'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  SOC Analyst
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={selectedRoleContext === ROLES.EXECUTIVE}
                  onClick={() => setSelectedRoleContext(ROLES.EXECUTIVE)}
                  className={`relative z-10 w-1/2 py-1.5 text-xs font-semibold tracking-tight transition-colors duration-150 cursor-pointer text-center ${
                    selectedRoleContext === ROLES.EXECUTIVE
                      ? 'text-slate-900 dark:text-white'
                      : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
                >
                  Executive
                </button>
              </div>
            </div>

            {/* Email Field */}
            <div>
              <label
                htmlFor="email-input"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Email
              </label>
              <input
                id="email-input"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@domain.com"
                disabled={isLoading}
                className="block w-full px-3.5 py-2.5 text-xs rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-[#080C14] text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-sky-500 dark:focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all duration-150"
              />
            </div>

            {/* Password Field with Toggle */}
            <div>
              <label
                htmlFor="password-input"
                className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password-input"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  disabled={isLoading}
                  className="block w-full pl-3.5 pr-10 py-2.5 text-xs rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-[#080C14] text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-sky-500 dark:focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition-all duration-150"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[17px]">
                    {showPassword ? 'visibility_off' : 'visibility'}
                  </span>
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 active:bg-sky-700 dark:bg-sky-600 dark:hover:bg-sky-500 shadow-xs hover:shadow-sm transition-all duration-150 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <span className="material-symbols-outlined text-[16px] animate-spin">
                      refresh
                    </span>
                    <span>Authenticating...</span>
                  </>
                ) : (
                  <span>Sign In</span>
                )}
              </button>
            </div>
          </form>
        </div>

        {/* Bottom space to balance layout */}
        <div className="h-6"></div>
      </div>
    </div>
  );
}

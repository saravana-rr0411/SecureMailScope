import React from 'react';
import BrandEmblem from './BrandEmblem';
import { ROLES } from '../utils/authRbac';

export default function TopAppBar({
  theme = 'light',
  onToggleTheme,
  userRole = ROLES.SOC_ANALYST,
  userEmail = '',
  onLogout,
}) {
  const isExecutive = userRole === ROLES.EXECUTIVE;

  return (
    <header className="fixed top-0 left-0 right-0 h-16 z-50 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 shadow-xs px-6 flex items-center justify-between transition-colors duration-150">
      {/* Left: Brand & Product */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <BrandEmblem className="w-8 h-8 rounded-lg shadow-xs" />
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-900 dark:text-white text-sm tracking-tight leading-tight">
                SecureMailScope
              </span>
              <span className="font-sans text-[11px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold border border-slate-200 dark:border-slate-700">
                v1.4
              </span>
            </div>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 block leading-tight font-normal">
              Cryptographic Security Posture & Forensics
            </span>
          </div>
        </div>
      </div>

      {/* Right: Workstation Mode, Identity & Theme Toggle */}
      <div className="flex items-center gap-3">
        <div className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700 font-sans text-[10px] font-semibold text-slate-600 dark:text-slate-300 tracking-wider uppercase">
          <span className={`w-1.5 h-1.5 rounded-full ${isExecutive ? 'bg-indigo-500' : 'bg-emerald-500'}`}></span>
          <span>{isExecutive ? 'Executive Workstation' : 'SOC Workstation'}</span>
        </div>

        {userEmail && (
          <span className="hidden md:inline-block text-xs text-slate-500 dark:text-slate-400 font-normal max-w-[200px] truncate">
            {userEmail}
          </span>
        )}

        {/* Dark / Light Mode Toggle Button */}
        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          className="inline-flex items-center justify-center w-8 h-8 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 active:bg-slate-200 dark:active:bg-slate-600 transition-all duration-150 cursor-pointer shadow-2xs"
        >
          <span className="material-symbols-outlined text-[17px]">
            {theme === 'dark' ? 'light_mode' : 'dark_mode'}
          </span>
        </button>

        {/* Quick Sign Out Action */}
        {onLogout && (
          <button
            type="button"
            onClick={onLogout}
            aria-label="Sign out"
            title="Sign out"
            className="inline-flex items-center justify-center w-8 h-8 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-all duration-150 cursor-pointer shadow-2xs"
          >
            <span className="material-symbols-outlined text-[17px]">logout</span>
          </button>
        )}
      </div>
    </header>
  );
}

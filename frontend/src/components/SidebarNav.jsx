import React from 'react';
import { getNavItemsForRole, ROLES } from '../utils/authRbac';

export default function SidebarNav({
  activeTab,
  onTabChange,
  userRole = ROLES.SOC_ANALYST,
  userEmail = '',
  onLogout,
}) {
  const navItems = getNavItemsForRole(userRole);

  const roleLabel =
    userRole === ROLES.EXECUTIVE ? 'Executive' : userRole === ROLES.SOC_ANALYST ? 'SOC Analyst' : 'User';

  return (
    <aside className="fixed left-0 top-16 bottom-0 w-60 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 z-40 flex flex-col justify-between p-4 transition-colors duration-150">
      <div className="space-y-6">
        <div>
          <div className="px-3 pb-2 text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider font-sans flex items-center justify-between">
            <span>{userRole === ROLES.EXECUTIVE ? 'Executive Workspace' : 'Forensics Workspace'}</span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-bold border border-slate-200 dark:border-slate-700">
              {roleLabel}
            </span>
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer text-left ${
                    isActive
                      ? 'bg-slate-900 dark:bg-slate-800 text-white shadow-xs font-semibold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100/80 dark:hover:bg-slate-800/60 active:bg-slate-200/60 dark:active:bg-slate-800'
                  }`}
                >
                  <span
                    className={`material-symbols-outlined text-[18px] ${
                      isActive ? 'text-white' : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Sidebar Footer: User identity & Logout */}
      <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2">
        {userEmail && (
          <div className="px-3 py-1.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800/80">
            <div className="text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider font-semibold">
              Authenticated As
            </div>
            <div className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate mt-0.5" title={userEmail}>
              {userEmail}
            </div>
          </div>
        )}

        <button
          type="button"
          onClick={onLogout}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 hover:text-rose-700 dark:hover:text-rose-300 transition-all duration-150 cursor-pointer"
        >
          <span className="material-symbols-outlined text-[18px]">logout</span>
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}

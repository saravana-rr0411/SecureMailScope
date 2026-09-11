import React from 'react';

export default function SidebarNav({ activeTab, onTabChange }) {
  const navItems = [
    { id: 'executive', label: 'Executive Dashboard', icon: 'shield' },
    { id: 'overview', label: 'Overview', icon: 'analytics' },
    { id: 'forensics', label: 'Forensics & AI Risk', icon: 'manage_search' },
  ];

  return (
    <aside className="fixed left-0 top-16 bottom-0 w-60 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 z-40 flex flex-col p-4 transition-colors duration-150">
      <div className="space-y-6">
        <div>
          <div className="px-3 pb-2 text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider font-sans">
            Forensics Workspace
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
                  <span className={`material-symbols-outlined text-[18px] ${isActive ? 'text-white' : 'text-slate-500 dark:text-slate-400'}`}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>
    </aside>
  );
}

import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Clock,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { useState } from 'react';

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/audit', icon: Clock, label: 'Audit Logs' },
];

const bottomNavItems = [
  { path: '/profile', icon: Settings, label: 'Profile' },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside
      className={`
        h-full flex flex-col
        bg-[var(--color-surface)]
        border-r border-[var(--color-border-light)]
        transition-all duration-300
        ${collapsed ? 'w-20' : 'w-64'}
      `}
    >
      {/* Logo */}
      <div className="h-16 flex items-center justify-center border-b border-[var(--color-border-light)]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[var(--color-gray-dark)] flex items-center justify-center shadow-lg overflow-hidden p-1">
            <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
          </div>
          {!collapsed && (
            <span className="text-xl font-bold text-[var(--color-text-primary)]">
              ModernAuth
            </span>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <div className="px-3 space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`
                  flex items-center gap-3 px-3 py-2.5 rounded-lg
                  transition-all duration-200
                  ${
                    isActive
                      ? 'bg-[var(--color-gray-dark)] text-white shadow-md'
                      : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-gray-light)]/20 hover:text-[var(--color-text-primary)]'
                  }
                `}
              >
                <item.icon
                  size={20}
                  className={isActive ? 'text-white' : ''}
                />
                {!collapsed && (
                  <span className="font-medium">{item.label}</span>
                )}
              </NavLink>
            );
          })}
        </div>
      </nav>

      {/* Bottom Navigation */}
      <div className="py-4 border-t border-[var(--color-border-light)]">
        <div className="px-3 space-y-1">
          {bottomNavItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`
                  flex items-center gap-3 px-3 py-2.5 rounded-lg
                  transition-all duration-200
                  ${
                    isActive
                      ? 'bg-[var(--color-gray-dark)] text-white'
                      : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-gray-light)]/20 hover:text-[var(--color-text-primary)]'
                  }
                `}
              >
                <item.icon size={20} />
                {!collapsed && (
                  <span className="font-medium">{item.label}</span>
                )}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* Collapse Button */}
      <div className="p-3 border-t border-[var(--color-border-light)]">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg
            text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]
            hover:bg-[var(--color-gray-light)]/20
            transition-all duration-200"
        >
          {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
          {!collapsed && <span className="text-sm">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}

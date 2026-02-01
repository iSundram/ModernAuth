import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Settings as SettingsIcon,
  Lock,
  ChevronLeft,
  ChevronRight,
  Key,
  Webhook,
  Mail,
  Link2,
  Clock,
} from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../../hooks/useAuth';

const navItems = [
  { path: '/user', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/user/security', icon: Lock, label: 'Security' },
  { path: '/user/audit', icon: Clock, label: 'Activity Log' },
  { path: '/user/connected-accounts', icon: Link2, label: 'Connected Accounts' },
  { path: '/user/api-keys', icon: Key, label: 'API Keys' },
  { path: '/user/webhooks', icon: Webhook, label: 'Webhooks' },
  { path: '/user/invitations', icon: Mail, label: 'Invitations' },
];

const bottomNavItems = [
  { path: '/user/settings', icon: SettingsIcon, label: 'Settings' },
];

export function UserSidebar() {
  const { settings } = useAuth();
  const [collapsed, setCollapsed] = useState(() => {
    // Load collapsed state from localStorage, default to true
    const saved = localStorage.getItem('userSidebarCollapsed');
    return saved ? JSON.parse(saved) : true;
  });
  const location = useLocation();

  // Save collapsed state to localStorage
  const toggleCollapsed = () => {
    const newState = !collapsed;
    setCollapsed(newState);
    localStorage.setItem('userSidebarCollapsed', JSON.stringify(newState));
  };

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
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#B3B3B3] to-[#D4D4D4] flex items-center justify-center shadow-lg overflow-hidden p-1">
            <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
          </div>
          {!collapsed && (
            <span className="text-xl font-bold text-[var(--color-text-primary)]">
              {settings['site.name'] || 'ModernAuth'}
            </span>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <div className="px-3 space-y-1">
          {navItems.map((item) => {
            // Exact match for dashboard, path-based match for others
            const isActive = item.path === '/user' 
              ? location.pathname === '/user'
              : location.pathname.startsWith(item.path);
            
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`
                  flex items-center gap-3 px-3 py-2.5 rounded-lg
                  transition-colors duration-200 outline-none focus:outline-none
                  ${
                    isActive
                      ? 'bg-[#D4D4D4] !text-[#2B2B2B] border-l-4 border-l-[#2B2B2B] shadow-sm'
                      : '!text-[var(--color-text-secondary)] hover:bg-[#D4D4D4]/50 hover:!text-[#2B2B2B] border-l-4 border-l-transparent'
                  }
                `}
              >
                <item.icon
                  size={20}
                  className={isActive ? 'text-[#2B2B2B]' : 'text-[#B3B3B3]'}
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
                  transition-colors duration-200 outline-none focus:outline-none
                  ${
                    isActive
                      ? 'bg-[#D4D4D4] !text-[#2B2B2B] border-l-4 border-l-[#2B2B2B] shadow-sm'
                      : '!text-[var(--color-text-secondary)] hover:bg-[#D4D4D4]/50 hover:!text-[#2B2B2B] border-l-4 border-l-transparent'
                  }
                `}
              >
                <item.icon 
                  size={20}
                  className={isActive ? 'text-[#2B2B2B]' : 'text-[#B3B3B3]'}
                />
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
          onClick={toggleCollapsed}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg
            text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]
            hover:bg-[#D4D4D4]/50
            transition-all duration-200"
        >
          {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
          {!collapsed && <span className="text-sm">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}

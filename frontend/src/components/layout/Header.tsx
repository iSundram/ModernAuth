import { Bell, Search, User, LogOut, ChevronDown } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { Input } from '../ui/Input';

export function Header() {
  const { user, logout } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="h-16 bg-[var(--color-surface)] border-b border-[var(--color-border-light)] px-6">
      <div className="h-full flex items-center justify-between">
        {/* Search */}
        <div className="flex-1 max-w-md">
          <Input
            placeholder="Search domains, databases, users..."
            leftIcon={<Search size={18} />}
            className="bg-[var(--color-gray-light)]/20"
          />
        </div>

        {/* Right Side */}
        <div className="flex items-center gap-4">
          {/* Notifications */}
          <button className="relative p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-gray-light)]/20 transition-all duration-200">
            <Bell size={20} />
            <span className="absolute top-1 right-1 w-2 h-2 bg-[var(--color-error)] rounded-full"></span>
          </button>

          {/* User Menu */}
          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--color-gray-light)]/20 transition-all duration-200"
            >
              <div className="w-8 h-8 rounded-full bg-[var(--color-gray-dark)] flex items-center justify-center">
                <User size={16} className="text-white" />
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  {user?.username || 'User'}
                </p>
                <p className="text-xs text-[var(--color-text-muted)]">
                  {user?.email || 'user@example.com'}
                </p>
              </div>
              <ChevronDown
                size={16}
                className={`text-[var(--color-text-muted)] transition-transform duration-200 ${
                  showUserMenu ? 'rotate-180' : ''
                }`}
              />
            </button>

            {/* Dropdown Menu */}
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-56 py-2 bg-[var(--color-surface)] rounded-lg shadow-xl border border-[var(--color-border-light)] z-50">
                <div className="px-4 py-2 border-b border-[var(--color-border-light)]">
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    {user?.username}
                  </p>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    {user?.email}
                  </p>
                </div>
                <div className="py-1">
                  <Link
                    to="/profile"
                    className="flex items-center gap-3 px-4 py-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-gray-light)]/20"
                  >
                    <User size={16} />
                    Profile
                  </Link>
                  <button
                    onClick={logout}
                    className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--color-error)] hover:bg-[var(--color-error)]/10"
                  >
                    <LogOut size={16} />
                    Sign out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}

import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Clock,
  Lock,
  User,
  Smartphone,
  Monitor,
  AlertCircle,
  CheckCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { LoadingBar, Badge } from '../components/ui';
import { OnboardingWizard } from '../components/onboarding';
import { useAuth } from '../hooks/useAuth';
import { deviceService, auditService, sessionService, authService } from '../api/services';
import { Link } from 'react-router-dom';
import type { AuditLog, Session, MFAStatus } from '../types';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  description?: string;
  variant?: 'default' | 'success' | 'warning' | 'error';
}

function StatCard({ title, value, icon, description, variant = 'default' }: StatCardProps) {
  const variantColors = {
    default: 'from-[#B3B3B3]/30 to-[#D4D4D4]/20',
    success: 'from-green-500/30 to-emerald-500/20',
    warning: 'from-yellow-500/30 to-amber-500/20',
    error: 'from-red-500/30 to-rose-500/20',
  };

  return (
    <Card hover>
      <CardContent className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-[var(--color-text-secondary)]">{title}</p>
          <p className="text-3xl font-bold text-[var(--color-text-primary)] mt-2">{value}</p>
          {description && (
            <p className="text-sm text-[var(--color-text-muted)] mt-2">{description}</p>
          )}
        </div>
        <div className={`p-3 rounded-xl bg-gradient-to-br ${variantColors[variant]}`}>
          {icon}
        </div>
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const { user } = useAuth();

  // Fetch devices
  const { data: devices = [], isLoading: devicesLoading } = useQuery({
    queryKey: ['devices'],
    queryFn: () => deviceService.list(),
  });

  // Active sessions
  const { data: sessions = [], isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions', 'dashboard'],
    queryFn: () => sessionService.list({ limit: 20, offset: 0 }),
  });

  // Fetch recent audit logs
  const { data: auditLogs = [], isLoading: auditLoading } = useQuery({
    queryKey: ['audit-logs', 'recent'],
    queryFn: () => auditService.listLogs({ limit: 5, offset: 0 }),
  });

  // Fetch MFA status for security score
  const { data: mfaStatus } = useQuery<MFAStatus>({
    queryKey: ['mfa-status', 'dashboard'],
    queryFn: () => authService.getMfaStatus(),
    retry: false,
  });

  const isLoading = devicesLoading || auditLoading || sessionsLoading;

  // Calculate stats
  const activeSessions = sessions.length;
  const trustedDevices = devices.filter(d => d.is_trusted).length;
  const isEmailVerified = user?.is_email_verified ?? false;
  const lastLogin = user?.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never';

  // Get security score
  const getSecurityScore = () => {
    let score = 0;
    if (isEmailVerified) score += 25;
    if (trustedDevices > 0) score += 25;
    if (activeSessions > 0) score += 25;
    const hasMfa =
      !!mfaStatus &&
      (mfaStatus.totp_enabled || mfaStatus.email_enabled || mfaStatus.webauthn_enabled);
    if (hasMfa) score += 25;
    return Math.min(score, 100);
  };

  const securityScore = getSecurityScore();
  const securityLevel = securityScore >= 75 ? 'Strong' : securityScore >= 50 ? 'Good' : 'Weak';

  return (
    <div className="space-y-6">
      <OnboardingWizard />
      <LoadingBar isLoading={isLoading} message="Loading dashboard..." />
      
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Dashboard</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Welcome back, {user?.first_name || user?.username || user?.email}! Here's an overview of your account security.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Account Status"
          value={user?.is_active ? 'Active' : 'Inactive'}
          icon={<User size={24} className="text-[#D4D4D4]" />}
          description={user?.is_active ? 'Your account is active' : 'Account is suspended'}
          variant={user?.is_active ? 'success' : 'error'}
        />
        <StatCard
          title="Security Score"
          value={securityLevel}
          icon={<Shield size={24} className={securityScore >= 75 ? 'text-green-500' : securityScore >= 50 ? 'text-yellow-500' : 'text-red-500'} />}
          description={`${securityScore}% - ${securityScore >= 75 ? 'Excellent' : securityScore >= 50 ? 'Good' : 'Needs improvement'}`}
          variant={securityScore >= 75 ? 'success' : securityScore >= 50 ? 'warning' : 'error'}
        />
        <StatCard
          title="Active Sessions"
          value={activeSessions}
          icon={<Monitor size={24} className="text-[#D4D4D4]" />}
          description={`${sessions.length} total sessions`}
        />
        <StatCard
          title="Trusted Devices"
          value={trustedDevices}
          icon={<Smartphone size={24} className="text-[#D4D4D4]" />}
          description={`${devices.length} total devices`}
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Security Events */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Security Events</CardTitle>
            <Link 
              to="/user/audit" 
              className="text-sm text-[var(--color-info)] hover:underline"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent>
            {auditLoading ? (
              <div className="text-center py-8 text-[var(--color-text-muted)]">Loading...</div>
            ) : auditLogs.length === 0 ? (
              <div className="text-center py-8 text-[var(--color-text-muted)]">
                No recent events
              </div>
            ) : (
              <div className="space-y-3">
                {auditLogs.slice(0, 5).map((log: AuditLog) => (
                  <div key={log.id} className="flex items-center gap-4 p-3 rounded-lg bg-[var(--color-surface-hover)]">
                    <div className={`p-2 rounded-lg ${
                      log.event_type.includes('success') || log.event_type.includes('verified')
                        ? 'bg-green-500/20'
                        : log.event_type.includes('failed') || log.event_type.includes('error')
                        ? 'bg-red-500/20'
                        : 'bg-[var(--color-primary-dark)]'
                    }`}>
                      {log.event_type.includes('login') || log.event_type.includes('logout') ? (
                        <Lock size={16} className={log.event_type.includes('success') ? 'text-green-500' : 'text-[#D4D4D4]'} />
                      ) : log.event_type.includes('mfa') || log.event_type.includes('verification') ? (
                        <Shield size={16} className={log.event_type.includes('success') ? 'text-green-500' : 'text-[#D4D4D4]'} />
                      ) : (
                        <Clock size={16} className="text-[#D4D4D4]" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-[var(--color-text-primary)] font-medium truncate">
                        {log.event_type.replace(/\./g, ' ').replace(/_/g, ' ')}
                      </p>
                      <p className="text-xs text-[var(--color-text-muted)]">
                        {new Date(log.created_at).toLocaleString()}
                        {log.ip && ` • ${log.ip}`}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Account Information */}
        <Card>
          <CardHeader>
            <CardTitle>Account Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Email</span>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-[var(--color-text-primary)]">{user?.email}</span>
                {isEmailVerified ? (
                  <Badge variant="success" size="sm">
                    <CheckCircle size={12} className="mr-1" />
                    Verified
                  </Badge>
                ) : (
                  <Badge variant="warning" size="sm">
                    <AlertCircle size={12} className="mr-1" />
                    Unverified
                  </Badge>
                )}
              </div>
            </div>
            <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Username</span>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{user?.username || 'Not set'}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Role</span>
              <Badge variant="default" size="sm" className="capitalize">
                {user?.role || 'user'}
              </Badge>
            </div>
            <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Last Login</span>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{lastLogin}</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-sm text-[var(--color-text-secondary)]">Member Since</span>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link to="/user/security">
          <Card hover className="cursor-pointer">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="p-3 rounded-lg bg-[var(--color-primary-dark)]">
                <Shield size={24} className="text-[#D4D4D4]" />
              </div>
              <div>
                <p className="font-medium text-[var(--color-text-primary)]">Security Settings</p>
                <p className="text-sm text-[var(--color-text-muted)]">Manage MFA, devices & sessions</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link to="/user/settings">
          <Card hover className="cursor-pointer">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="p-3 rounded-lg bg-[var(--color-primary-dark)]">
                <User size={24} className="text-[#D4D4D4]" />
              </div>
              <div>
                <p className="font-medium text-[var(--color-text-primary)]">Account Settings</p>
                <p className="text-sm text-[var(--color-text-muted)]">Update your profile</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link to="/user/audit">
          <Card hover className="cursor-pointer">
            <CardContent className="flex items-center gap-4 p-6">
              <div className="p-3 rounded-lg bg-[var(--color-primary-dark)]">
                <Clock size={24} className="text-[#D4D4D4]" />
              </div>
              <div>
                <p className="font-medium text-[var(--color-text-primary)]">Audit Logs</p>
                <p className="text-sm text-[var(--color-text-muted)]">View activity history</p>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  );
}

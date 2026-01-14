import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Users,
  Lock,
  Key,
  Eye,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button } from '../../components/ui';
import { adminService, auditService, userService } from '../../api/services';
import { Link } from 'react-router-dom';
import type { AuditLog } from '../../types';

export function AdminSecurityPage() {
  // Fetch system stats
  useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminService.getSystemStats(),
  });

  // Fetch service status
  const { data: services = [] } = useQuery({
    queryKey: ['admin-services'],
    queryFn: () => adminService.getServiceStatus(),
  });

  // Fetch all users for security stats
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: () => userService.list(),
  });

  // Fetch recent security events
  const { data: securityLogs = [] } = useQuery({
    queryKey: ['admin-security-logs'],
    queryFn: () => auditService.listLogs({ 
      limit: 20,
      event_type: undefined, // Get all events, we'll filter client-side
    }),
  });

  // Calculate security metrics
  const usersWithMfa = users.filter(_u => {
    // Note: MFA status might not be in user object, this is a placeholder
    // In a real implementation, you'd need an endpoint to get MFA status
    return false; // Placeholder
  }).length;

  const verifiedUsers = users.filter(u => u.is_email_verified).length;
  const activeUsers = users.filter(u => u.is_active).length;
  const suspendedUsers = users.filter(u => !u.is_active).length;

  // Filter security-related events
  const recentSecurityEvents = securityLogs
    .filter((log: AuditLog) => 
      log.event_type.includes('login') || 
      log.event_type.includes('mfa') || 
      log.event_type.includes('password') ||
      log.event_type.includes('security') ||
      log.event_type.includes('failed') ||
      log.event_type.includes('revoke')
    )
    .slice(0, 10);

  const getEventBadge = (eventType: string) => {
    const type = eventType.toLowerCase();
    if (type.includes('success') || type.includes('verified')) {
      return <Badge variant="success" size="sm">Secure</Badge>;
    }
    if (type.includes('failed') || type.includes('error') || type.includes('revoke')) {
      return <Badge variant="error" size="sm">Alert</Badge>;
    }
    if (type.includes('mfa') || type.includes('password')) {
      return <Badge variant="warning" size="sm">Security</Badge>;
    }
    return <Badge variant="default" size="sm">Info</Badge>;
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Security Administration</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Monitor security events, user security status, and system health
        </p>
      </div>

      {/* Security Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{verifiedUsers}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Verified Users</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-blue-500/10">
              <Shield size={24} className="text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{usersWithMfa}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">MFA Enabled</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-yellow-500/10">
              <AlertTriangle size={24} className="text-yellow-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{suspendedUsers}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Suspended</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-[#B3B3B3]/30">
              <Activity size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{recentSecurityEvents.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Recent Events</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Security Status */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>User Security Status</CardTitle>
            <Link 
              to="/admin/users" 
              className="text-sm text-[var(--color-info)] hover:underline"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Total Users</span>
              <span className="text-lg font-bold text-[var(--color-text-primary)]">
                {users.length}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Active Users</span>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-[var(--color-text-primary)]">
                  {activeUsers}
                </span>
                <Badge variant="success" size="sm">Active</Badge>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Email Verified</span>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-[var(--color-text-primary)]">
                  {verifiedUsers}
                </span>
                <Badge variant="success" size="sm">
                  {users.length > 0 ? Math.round((verifiedUsers / users.length) * 100) : 0}%
                </Badge>
              </div>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-sm text-[var(--color-text-secondary)]">Suspended</span>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-[var(--color-text-primary)]">
                  {suspendedUsers}
                </span>
                <Badge variant="error" size="sm">Suspended</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Service Health */}
        <Card>
          <CardHeader>
            <CardTitle>Service Health</CardTitle>
          </CardHeader>
          <CardContent>
            {services.length === 0 ? (
              <div className="text-center py-8 text-[var(--color-text-muted)]">
                No services configured
              </div>
            ) : (
              <div className="space-y-3">
                {services.map((service) => (
                  <div
                    key={service.name}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                  >
                    <div className="flex items-center gap-3">
                      {service.status === 'healthy' ? (
                        <CheckCircle size={20} className="text-green-500" />
                      ) : service.status === 'degraded' ? (
                        <AlertTriangle size={20} className="text-yellow-500" />
                      ) : (
                        <XCircle size={20} className="text-red-500" />
                      )}
                      <div>
                        <span className="text-sm font-medium text-[var(--color-text-primary)]">
                          {service.name}
                        </span>
                        {service.version && (
                          <p className="text-xs text-[var(--color-text-muted)]">v{service.version}</p>
                        )}
                      </div>
                    </div>
                    <Badge
                      variant={
                        service.status === 'healthy' 
                          ? 'success' 
                          : service.status === 'degraded'
                          ? 'warning'
                          : 'error'
                      }
                      size="sm"
                    >
                      {service.status}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Security Events */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Recent Security Events</CardTitle>
          <Link 
            to="/admin/audit" 
            className="text-sm text-[var(--color-info)] hover:underline"
          >
            View all logs
          </Link>
        </CardHeader>
        <CardContent>
          {recentSecurityEvents.length === 0 ? (
            <div className="text-center py-8 text-[var(--color-text-muted)]">
              <Shield size={48} className="mx-auto mb-4 opacity-50" />
              <p className="text-[var(--color-text-secondary)]">No recent security events</p>
            </div>
          ) : (
            <div className="space-y-3">
              {recentSecurityEvents.map((log: AuditLog) => (
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
                      <Key size={16} className={log.event_type.includes('success') ? 'text-green-500' : 'text-[#D4D4D4]'} />
                    ) : (
                      <Shield size={16} className="text-[#D4D4D4]" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <p className="text-sm text-[var(--color-text-primary)] font-medium truncate">
                        {log.event_type.replace(/\./g, ' ').replace(/_/g, ' ')}
                      </p>
                      {getEventBadge(log.event_type)}
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)]">
                      {new Date(log.created_at).toLocaleString()}
                      {log.ip && ` • ${log.ip}`}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Link to="/admin/audit">
                      <Button variant="ghost" size="sm" title="View Details">
                        <Eye size={16} />
                      </Button>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security Features Info */}
      <Card>
        <CardHeader>
          <CardTitle>Security Features</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
              <div className="flex items-center gap-3 mb-2">
                <Shield size={20} className="text-[#D4D4D4]" />
                <h3 className="font-medium text-[var(--color-text-primary)]">Multi-Factor Authentication</h3>
              </div>
              <p className="text-sm text-[var(--color-text-secondary)]">
                Users can enable TOTP-based MFA for enhanced account security
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
              <div className="flex items-center gap-3 mb-2">
                <Key size={20} className="text-[#D4D4D4]" />
                <h3 className="font-medium text-[var(--color-text-primary)]">Role-Based Access Control</h3>
              </div>
              <p className="text-sm text-[var(--color-text-secondary)]">
                Fine-grained permissions and role management system
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
              <div className="flex items-center gap-3 mb-2">
                <Activity size={20} className="text-[#D4D4D4]" />
                <h3 className="font-medium text-[var(--color-text-primary)]">Audit Logging</h3>
              </div>
              <p className="text-sm text-[var(--color-text-secondary)]">
                Comprehensive audit trail of all system events and user actions
              </p>
            </div>
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
              <div className="flex items-center gap-3 mb-2">
                <Lock size={20} className="text-[#D4D4D4]" />
                <h3 className="font-medium text-[var(--color-text-primary)]">Session Management</h3>
              </div>
              <p className="text-sm text-[var(--color-text-secondary)]">
                Device tracking, session revocation, and login history monitoring
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Link
              to="/admin/users"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Users size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Manage Users</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">View and manage user accounts</p>
            </Link>
            <Link
              to="/admin/audit"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Activity size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Audit Logs</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">View system activity logs</p>
            </Link>
            <Link
              to="/admin/settings"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Lock size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">System Settings</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">Configure system settings</p>
            </Link>
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] opacity-50">
              <Shield size={24} className="text-[var(--color-text-muted)] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-muted)]">Firewall Rules</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">Coming soon</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

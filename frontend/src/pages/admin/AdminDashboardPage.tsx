import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Users,
  Activity,
  Shield,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Server,
  Lock,
  KeyRound,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Badge } from '../../components/ui';
import { adminService, userService } from '../../api/services';
import { useNavigate } from 'react-router-dom';
import { Link } from 'react-router-dom';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color?: 'primary' | 'success' | 'warning' | 'error';
  onClick?: () => void;
  subtitle?: string;
}

function StatCard({ title, value, icon, color = 'primary', onClick, subtitle }: StatCardProps) {
  const colorClasses = {
    primary: 'from-[#B3B3B3]/30 to-[#D4D4D4]/20',
    success: 'from-green-500/30 to-emerald-500/20',
    warning: 'from-yellow-500/30 to-amber-500/20',
    error: 'from-red-500/30 to-rose-500/20',
  };

  return (
    <Card hover className={onClick ? 'cursor-pointer' : ''} onClick={onClick}>
      <CardContent className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-[var(--color-text-secondary)]">{title}</p>
          <p className="text-3xl font-bold text-[var(--color-text-primary)] mt-2">{value}</p>
          {subtitle && (
            <p className="text-xs text-[var(--color-text-muted)] mt-1">{subtitle}</p>
          )}
        </div>
        <div className={`p-3 rounded-xl bg-gradient-to-br ${colorClasses[color]}`}>
          {icon}
        </div>
      </CardContent>
    </Card>
  );
}

// Simple bar chart component
function BarChart({ data, title }: { data: { label: string; value: number; color: string }[]; title: string }) {
  const maxValue = Math.max(...data.map(d => d.value), 1);
  
  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium text-[var(--color-text-secondary)]">{title}</h4>
      <div className="space-y-2">
        {data.map((item, index) => (
          <div key={index} className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">{item.label}</span>
              <span className="font-medium text-[var(--color-text-primary)]">{item.value}</span>
            </div>
            <div className="h-2 rounded-full bg-[var(--color-border)] overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${item.color}`}
                style={{ width: `${(item.value / maxValue) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Donut chart component
function DonutChart({ data, centerLabel, centerValue }: { 
  data: { label: string; value: number; color: string }[]; 
  centerLabel: string;
  centerValue: number;
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  let cumulativePercent = 0;
  
  const segments = data.map(item => {
    const percent = (item.value / total) * 100;
    const startPercent = cumulativePercent;
    cumulativePercent += percent;
    return { ...item, percent, startPercent };
  });

  // Create conic gradient
  const gradient = segments
    .map(s => `${s.color} ${s.startPercent}% ${s.startPercent + s.percent}%`)
    .join(', ');

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-32 h-32 shrink-0">
        <div
          className="w-full h-full rounded-full"
          style={{
            background: total > 0 
              ? `conic-gradient(${gradient})` 
              : 'var(--color-border)',
          }}
        />
        <div className="absolute inset-3 rounded-full bg-[var(--color-surface)] flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-[var(--color-text-primary)]">{centerValue}</span>
          <span className="text-xs text-[var(--color-text-muted)]">{centerLabel}</span>
        </div>
      </div>
      <div className="flex-1 space-y-2">
        {data.map((item, index) => (
          <div key={index} className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${item.color}`} />
            <span className="text-sm text-[var(--color-text-secondary)] flex-1">{item.label}</span>
            <span className="text-sm font-medium text-[var(--color-text-primary)]">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AdminDashboardPage() {
  const navigate = useNavigate();
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Fetch system stats
  const { data: systemStats, refetch: refetchStats } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminService.getSystemStats(),
    refetchInterval: 30000, // Auto-refresh every 30 seconds
  });

  // Fetch service status
  const { data: services = [], isLoading: servicesLoading } = useQuery({
    queryKey: ['admin-services'],
    queryFn: () => adminService.getServiceStatus(),
    refetchInterval: 30000,
  });

  // Fetch all users for additional stats
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: () => userService.list(),
  });

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await Promise.all([refetchStats()]);
    setIsRefreshing(false);
  };

  // Calculate additional stats
  const verifiedUsers = users.filter(u => u.is_email_verified).length;
  const activeUsers = systemStats?.users?.active || 0;
  const adminUsers = systemStats?.users?.byRole?.admin || 0;
  const regularUsers = systemStats?.users?.byRole?.user || 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">System Dashboard</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Overview of system health, users, and activity
          </p>
        </div>
        <Button
          variant="ghost"
          onClick={handleRefresh}
          disabled={isRefreshing}
          leftIcon={<RefreshCw size={18} className={isRefreshing ? 'animate-spin' : ''} />}
        >
          {isRefreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </div>

      {/* System Health Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Users"
          value={systemStats?.users.total || 0}
          icon={<Users size={24} className="text-[#D4D4D4]" />}
          onClick={() => navigate('/admin/users')}
          color="primary"
        />
        <StatCard
          title="Active Users"
          value={activeUsers}
          icon={<Activity size={24} className="text-green-500" />}
          onClick={() => navigate('/admin/users')}
          color="success"
        />
        <StatCard
          title="Admins"
          value={adminUsers}
          icon={<Shield size={24} className="text-[#D4D4D4]" />}
          onClick={() => navigate('/admin/users')}
          color="primary"
        />
        <StatCard
          title="Verified Users"
          value={verifiedUsers}
          icon={<CheckCircle size={24} className="text-green-500" />}
          color="success"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Distribution Chart */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>User Distribution</CardTitle>
            <Link 
              to="/admin/users" 
              className="text-sm text-[var(--color-info)] hover:underline"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent>
            <DonutChart
              data={[
                { label: 'Active', value: activeUsers, color: 'bg-green-500' },
                { label: 'Suspended', value: systemStats?.users.suspended || 0, color: 'bg-yellow-500' },
                { label: 'Unverified', value: (systemStats?.users.total || 0) - verifiedUsers, color: 'bg-gray-400' },
              ]}
              centerLabel="Total"
              centerValue={systemStats?.users.total || 0}
            />
          </CardContent>
        </Card>

        {/* Security Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound size={18} />
              Security Overview
            </CardTitle>
          </CardHeader>
          <CardContent>
            <BarChart
              title="User Security Status"
              data={[
                { label: 'Email Verified', value: verifiedUsers, color: 'bg-green-500' },
                { label: 'Active Users', value: activeUsers, color: 'bg-blue-500' },
                { label: 'Admins', value: adminUsers, color: 'bg-purple-500' },
                { label: 'Regular Users', value: regularUsers, color: 'bg-gray-400' },
              ]}
            />
          </CardContent>
        </Card>

        {/* User Statistics */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>User Statistics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Total Users</span>
              <span className="text-lg font-bold text-[var(--color-text-primary)]">
                {systemStats?.users.total || 0}
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Active</span>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-[var(--color-text-primary)]">
                  {activeUsers}
                </span>
                <Badge variant="success" size="sm">Active</Badge>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Suspended</span>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold text-[var(--color-text-primary)]">
                  {systemStats?.users.suspended || 0}
                </span>
                <Badge variant="warning" size="sm">Suspended</Badge>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Admins</span>
              <Badge variant="default" size="sm">{adminUsers}</Badge>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-sm text-[var(--color-text-secondary)]">Regular Users</span>
              <Badge variant="default" size="sm">{regularUsers}</Badge>
            </div>
          </CardContent>
        </Card>

        {/* Service Status */}
        <Card>
          <CardHeader>
            <CardTitle>Service Status</CardTitle>
          </CardHeader>
          <CardContent>
            {servicesLoading ? (
              <div className="text-center py-8 text-[var(--color-text-muted)]">Loading...</div>
            ) : services.length === 0 ? (
              <div className="text-center py-8 text-[var(--color-text-muted)]">
                No services configured
              </div>
            ) : (
              <div className="space-y-3">
                {services.map((service) => (
                  <div
                    key={service.name}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)]"
                  >
                    <div className="flex items-center gap-3">
                      {service.status === 'healthy' ? (
                        <CheckCircle size={20} className="text-green-500" />
                      ) : service.status === 'degraded' ? (
                        <AlertCircle size={20} className="text-yellow-500" />
                      ) : (
                        <AlertCircle size={20} className="text-red-500" />
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
                    <div className="flex items-center gap-2">
                      {service.uptime && (
                        <span className="text-xs text-[var(--color-text-muted)]">{service.uptime}</span>
                      )}
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
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

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
              <p className="text-xs text-[var(--color-text-muted)] mt-1">View and manage all users</p>
            </Link>
            <Link
              to="/admin/audit"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Server size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Audit Logs</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">View system activity</p>
            </Link>
            <Link
              to="/admin/security"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Shield size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Security</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">Security settings</p>
            </Link>
            <Link
              to="/admin/settings"
              className="p-4 rounded-lg bg-[var(--color-surface-hover)] hover:bg-[var(--color-primary-dark)]/50 transition-colors text-left"
            >
              <Lock size={24} className="text-[#D4D4D4] mb-2" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Settings</p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">System configuration</p>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

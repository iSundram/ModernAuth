import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Users,
  Activity,
  Shield,
  TrendingUp,
  TrendingDown,
  BarChart3,
  PieChart,
  RefreshCw,
  Calendar,
  Lock,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Badge } from '../../components/ui';
import { analyticsService } from '../../api/services';

// ============================================================================
// Stat Card Component
// ============================================================================

interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  icon: React.ReactNode;
  color?: 'primary' | 'success' | 'warning' | 'error';
}

function StatCard({ title, value, change, changeLabel, icon, color = 'primary' }: StatCardProps) {
  const colorClasses = {
    primary: 'from-blue-500/30 to-blue-600/20',
    success: 'from-green-500/30 to-emerald-500/20',
    warning: 'from-yellow-500/30 to-amber-500/20',
    error: 'from-red-500/30 to-rose-500/20',
  };

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-[var(--color-text-secondary)]">{title}</p>
            <p className="text-3xl font-bold text-[var(--color-text-primary)] mt-2">{value}</p>
            {change !== undefined && (
              <div className="flex items-center gap-1 mt-2">
                {change >= 0 ? (
                  <TrendingUp className="w-4 h-4 text-green-500" />
                ) : (
                  <TrendingDown className="w-4 h-4 text-red-500" />
                )}
                <span className={`text-sm ${change >= 0 ? 'text-green-500' : 'text-red-500'}`}>
                  {change >= 0 ? '+' : ''}{change.toFixed(1)}%
                </span>
                {changeLabel && (
                  <span className="text-xs text-[var(--color-text-muted)]">{changeLabel}</span>
                )}
              </div>
            )}
          </div>
          <div className={`p-3 rounded-xl bg-gradient-to-br ${colorClasses[color]}`}>
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Line Chart Component (Simple CSS-based)
// ============================================================================

interface LineChartProps {
  data: { label: string; value: number }[];
  height?: number;
}

function LineChart({ data, height = 200 }: LineChartProps) {
  if (!data || data.length === 0) {
    return <div className="text-center text-[var(--color-text-muted)] py-8">No data available</div>;
  }

  const maxValue = Math.max(...data.map(d => d.value), 1);
  const minValue = Math.min(...data.map(d => d.value), 0);
  const range = maxValue - minValue || 1;

  return (
    <div className="relative" style={{ height }}>
      {/* Y-axis labels */}
      <div className="absolute left-0 top-0 bottom-4 w-10 flex flex-col justify-between text-xs text-[var(--color-text-muted)]">
        <span>{maxValue}</span>
        <span>{Math.round(maxValue / 2)}</span>
        <span>{minValue}</span>
      </div>
      
      {/* Chart area */}
      <div className="ml-12 h-full flex items-end gap-1">
        {data.map((point, index) => {
          const barHeight = ((point.value - minValue) / range) * 100;
          return (
            <div
              key={index}
              className="flex-1 flex flex-col items-center"
              title={`${point.label}: ${point.value}`}
            >
              <div
                className="w-full bg-gradient-to-t from-blue-500 to-blue-400 rounded-t transition-all duration-300 hover:from-blue-600 hover:to-blue-500"
                style={{ height: `${Math.max(barHeight, 2)}%` }}
              />
              {data.length <= 14 && (
                <span className="text-[10px] text-[var(--color-text-muted)] mt-1 truncate max-w-full">
                  {point.label.slice(5)}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================================
// Donut Chart Component
// ============================================================================

interface DonutChartProps {
  data: { label: string; value: number; color: string }[];
  centerLabel: string;
  centerValue: string | number;
}

function DonutChart({ data, centerLabel, centerValue }: DonutChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;

  const segments = data.reduce<Array<{ color: string; value: number; percent: number; startPercent: number }>>((acc, item) => {
    const percent = (item.value / total) * 100;
    const startPercent = acc.length > 0 ? acc[acc.length - 1].startPercent + acc[acc.length - 1].percent : 0;
    acc.push({ ...item, percent, startPercent });
    return acc;
  }, []);

  const gradient = segments
    .map(s => `${s.color} ${s.startPercent}% ${s.startPercent + s.percent}%`)
    .join(', ');

  return (
    <div className="flex items-center gap-6">
      <div
        className="relative w-32 h-32 rounded-full"
        style={{ background: `conic-gradient(${gradient})` }}
      >
        <div className="absolute inset-4 bg-[var(--color-bg-primary)] rounded-full flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-[var(--color-text-primary)]">{centerValue}</span>
          <span className="text-xs text-[var(--color-text-muted)]">{centerLabel}</span>
        </div>
      </div>
      <div className="space-y-2">
        {data.map((item, index) => (
          <div key={index} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
            <span className="text-sm text-[var(--color-text-secondary)]">{item.label}</span>
            <span className="text-sm font-medium text-[var(--color-text-primary)]">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Main Analytics Page
// ============================================================================

export default function AdminAnalyticsPage() {
  const [timeRange, setTimeRange] = useState(7);

  const { data: overview, isLoading: overviewLoading, refetch: refetchOverview } = useQuery({
    queryKey: ['analytics', 'overview'],
    queryFn: () => analyticsService.getOverview(),
    refetchInterval: 30000, // Refresh every 30s
  });

  const { data: userAnalytics, isLoading: userLoading } = useQuery({
    queryKey: ['analytics', 'users'],
    queryFn: () => analyticsService.getUserAnalytics(),
    refetchInterval: 30000,
  });

  const { data: authAnalytics, isLoading: authLoading } = useQuery({
    queryKey: ['analytics', 'auth', timeRange],
    queryFn: () => analyticsService.getAuthAnalytics(timeRange),
    refetchInterval: 30000,
  });

  const { data: securityAnalytics, isLoading: securityLoading } = useQuery({
    queryKey: ['analytics', 'security'],
    queryFn: () => analyticsService.getSecurityAnalytics(),
    refetchInterval: 30000,
  });

  const isLoading = overviewLoading || userLoading || authLoading || securityLoading;

  const handleRefresh = () => {
    refetchOverview();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Analytics</h1>
          <p className="text-[var(--color-text-secondary)]">Real-time insights and metrics</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(Number(e.target.value))}
            className="px-3 py-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-primary)] text-sm"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <Button variant="outline" onClick={handleRefresh} disabled={isLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Users"
          value={overview?.total_users || 0}
          icon={<Users className="w-6 h-6 text-blue-500" />}
          color="primary"
        />
        <StatCard
          title="Daily Active Users"
          value={overview?.dau || 0}
          icon={<Activity className="w-6 h-6 text-green-500" />}
          color="success"
        />
        <StatCard
          title="MFA Adoption"
          value={`${(overview?.mfa_adoption_rate || 0).toFixed(1)}%`}
          icon={<Shield className="w-6 h-6 text-purple-500" />}
          color="primary"
        />
        <StatCard
          title="New This Week"
          value={overview?.new_users_this_week || 0}
          icon={<TrendingUp className="w-6 h-6 text-yellow-500" />}
          color="warning"
        />
      </div>

      {/* User Engagement Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="w-5 h-5" />
              User Engagement
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Daily Active (DAU)</span>
                <span className="font-bold text-[var(--color-text-primary)]">{overview?.dau || 0}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Weekly Active (WAU)</span>
                <span className="font-bold text-[var(--color-text-primary)]">{overview?.wau || 0}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Monthly Active (MAU)</span>
                <span className="font-bold text-[var(--color-text-primary)]">{overview?.mau || 0}</span>
              </div>
              <hr className="border-[var(--color-border)]" />
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Verified Users</span>
                <span className="font-bold text-green-500">{(overview?.verified_users_rate || 0).toFixed(1)}%</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PieChart className="w-5 h-5" />
              User Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DonutChart
              data={[
                { label: 'Verified', value: userAnalytics?.verified_users || 0, color: '#22c55e' },
                { label: 'Unverified', value: userAnalytics?.unverified_users || 0, color: '#ef4444' },
              ]}
              centerLabel="Total"
              centerValue={userAnalytics?.total_users || 0}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Security Overview
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Users with MFA</span>
                <Badge variant="success">{userAnalytics?.users_with_mfa || 0}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Failed MFA Attempts</span>
                <Badge variant="warning">{securityAnalytics?.failed_mfa_attempts || 0}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Suspicious Logins</span>
                <Badge variant="error">{securityAnalytics?.suspicious_logins || 0}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-[var(--color-text-secondary)]">Blocked IPs</span>
                <Badge variant="error">{securityAnalytics?.blocked_ips || 0}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Authentication Trends */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5" />
              Login Trends
            </CardTitle>
          </CardHeader>
          <CardContent>
            <LineChart
              data={(authAnalytics?.logins_by_day || []).map(d => ({
                label: d.date,
                value: d.value,
              }))}
              height={200}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="w-5 h-5" />
              Authentication Stats
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 rounded-lg bg-[var(--color-bg-secondary)]">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span className="text-sm text-[var(--color-text-secondary)]">Successful</span>
                </div>
                <p className="text-2xl font-bold text-green-500">{authAnalytics?.successful_logins || 0}</p>
              </div>
              <div className="p-4 rounded-lg bg-[var(--color-bg-secondary)]">
                <div className="flex items-center gap-2 mb-2">
                  <XCircle className="w-5 h-5 text-red-500" />
                  <span className="text-sm text-[var(--color-text-secondary)]">Failed</span>
                </div>
                <p className="text-2xl font-bold text-red-500">{authAnalytics?.failed_logins || 0}</p>
              </div>
              <div className="p-4 rounded-lg bg-[var(--color-bg-secondary)]">
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="w-5 h-5 text-purple-500" />
                  <span className="text-sm text-[var(--color-text-secondary)]">MFA Challenges</span>
                </div>
                <p className="text-2xl font-bold text-purple-500">{authAnalytics?.mfa_challenges || 0}</p>
              </div>
              <div className="p-4 rounded-lg bg-[var(--color-bg-secondary)]">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="w-5 h-5 text-blue-500" />
                  <span className="text-sm text-[var(--color-text-secondary)]">Success Rate</span>
                </div>
                <p className="text-2xl font-bold text-blue-500">{(authAnalytics?.success_rate || 0).toFixed(1)}%</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Signups */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Calendar className="w-5 h-5" />
            Recent Signups
          </CardTitle>
        </CardHeader>
        <CardContent>
          <LineChart
            data={(userAnalytics?.recent_signups || []).map(d => ({
              label: d.date,
              value: d.count,
            }))}
            height={150}
          />
        </CardContent>
      </Card>

      {/* Security Events */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Recent Security Events
          </CardTitle>
        </CardHeader>
        <CardContent>
          {securityAnalytics?.security_events && securityAnalytics.security_events.length > 0 ? (
            <div className="space-y-2">
              {securityAnalytics.security_events.slice(0, 10).map((event) => (
                <div
                  key={event.id}
                  className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-bg-secondary)]"
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-full ${
                      event.type.includes('failure') ? 'bg-red-500/20' :
                      event.type.includes('suspicious') ? 'bg-yellow-500/20' :
                      'bg-blue-500/20'
                    }`}>
                      {event.type.includes('failure') ? (
                        <XCircle className="w-4 h-4 text-red-500" />
                      ) : event.type.includes('suspicious') ? (
                        <AlertTriangle className="w-4 h-4 text-yellow-500" />
                      ) : (
                        <Shield className="w-4 h-4 text-blue-500" />
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-[var(--color-text-primary)]">
                        {event.type.replace(/\./g, ' ').replace(/_/g, ' ')}
                      </p>
                      <p className="text-xs text-[var(--color-text-muted)]">
                        IP: {event.ip || 'Unknown'}
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-[var(--color-text-muted)]">
                    {new Date(event.created_at).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-[var(--color-text-muted)] py-8">
              No security events in the selected period
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

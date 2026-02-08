import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Users,
  UserCheck,
  Clock,
  Search,
  Filter,
  Eye,
  Calendar,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button, Input, LoadingBar, EmptyState } from '../../components/ui';
import { adminService, userService } from '../../api/services';
import type { ImpersonationSession, User } from '../../types';

// Helper function for duration formatting - defined outside component for purity
const formatDuration = (start: string, end?: string) => {
  const startTime = new Date(start).getTime();
  const endTime = end ? new Date(end).getTime() : Date.now();
  const durationMs = endTime - startTime;
  
  const seconds = Math.floor(durationMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
};

export function AdminImpersonationPage() {
  const [filterAdminId, setFilterAdminId] = useState('');
  const [filterTargetId, setFilterTargetId] = useState('');

  // Fetch impersonation sessions
  const { data: sessionsData, isLoading, refetch, isError: sessionsError } = useQuery({
    queryKey: ['impersonation-sessions', filterAdminId, filterTargetId],
    queryFn: () => adminService.listImpersonationSessions({
      admin_user_id: filterAdminId || undefined,
      target_user_id: filterTargetId || undefined,
      limit: 100,
    }),
  });

  const sessions = sessionsData?.sessions || [];

  // Fetch users for display names
  const { data: users = [], isError: usersError } = useQuery({
    queryKey: ['users-for-display'],
    queryFn: () => userService.list(),
  });

  // Create a user lookup map
  const userMap = users.reduce((acc: Record<string, User>, user) => {
    acc[user.id] = user;
    return acc;
  }, {});

  const getUserDisplayName = (userId: string) => {
    const user = userMap[userId];
    if (user) {
      if (user.first_name || user.last_name) {
        return `${user.first_name || ''} ${user.last_name || ''}`.trim();
      }
      return user.email;
    }
    return userId.slice(0, 8) + '...';
  };

  const getStatusBadge = (session: ImpersonationSession) => {
    if (session.ended_at) {
      return <Badge variant="default" size="sm">Ended</Badge>;
    }
    return <Badge variant="success" size="sm">Active</Badge>;
  };

  // Calculate stats
  const activeSessions = sessions.filter(s => !s.ended_at).length;
  const totalSessions = sessions.length;
  const uniqueAdmins = new Set(sessions.map(s => s.admin_user_id)).size;
  const uniqueTargets = new Set(sessions.map(s => s.target_user_id)).size;

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading} message="Loading impersonation sessions..." />
      
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Impersonation Sessions</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Monitor and audit admin impersonation activity
          </p>
        </div>
        <Button variant="ghost" onClick={() => refetch()}>
          <RefreshCw size={16} className="mr-2" />
          Refresh
        </Button>
      </div>

      {/* Error Display */}
      {sessionsError && (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-red-500/10 border border-red-500/20">
          <AlertCircle size={20} className="text-red-500" />
          <span className="text-sm text-red-500">Failed to load impersonation sessions. Please try again.</span>
        </div>
      )}

      {usersError && (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
          <AlertCircle size={20} className="text-yellow-500" />
          <span className="text-sm text-yellow-600">Unable to load user names. User IDs will be displayed instead.</span>
        </div>
      )}

      {/* Stats Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-blue-500/10">
              <Users size={24} className="text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{totalSessions}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Sessions</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <UserCheck size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{activeSessions}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Active Now</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-purple-500/10">
              <Eye size={24} className="text-purple-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{uniqueAdmins}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Unique Admins</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-orange-500/10">
              <Users size={24} className="text-orange-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{uniqueTargets}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Unique Targets</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Filter size={18} className="text-[var(--color-text-muted)]" />
            <CardTitle>Filters</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <Input
              placeholder="Filter by Admin User ID"
              value={filterAdminId}
              onChange={(e) => setFilterAdminId(e.target.value)}
              leftIcon={<Search size={16} />}
              className="flex-1"
            />
            <Input
              placeholder="Filter by Target User ID"
              value={filterTargetId}
              onChange={(e) => setFilterTargetId(e.target.value)}
              leftIcon={<Search size={16} />}
              className="flex-1"
            />
            {(filterAdminId || filterTargetId) && (
              <Button 
                variant="ghost" 
                onClick={() => {
                  setFilterAdminId('');
                  setFilterTargetId('');
                }}
              >
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Sessions List */}
      <Card>
        <CardHeader>
          <CardTitle>Session History</CardTitle>
        </CardHeader>
        <CardContent>
          {sessions.length === 0 ? (
            <EmptyState
              icon={<Users size={48} className="text-[var(--color-text-muted)]" />}
              title="No impersonation sessions"
              description="No impersonation sessions found matching your criteria."
            />
          ) : (
            <div className="space-y-3">
              {sessions.map((session: ImpersonationSession) => (
                <div 
                  key={session.id} 
                  className={`p-4 rounded-lg border ${
                    session.ended_at 
                      ? 'bg-[var(--color-surface)] border-[var(--color-border)]'
                      : 'bg-green-500/5 border-green-500/20'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    {/* Admin Info */}
                    <div className="flex items-center gap-4 min-w-0">
                      <div className="p-2 rounded-lg bg-[var(--color-surface-hover)]">
                        <Eye size={20} className="text-[var(--color-text-muted)]" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium text-[var(--color-text-primary)]">
                            {getUserDisplayName(session.admin_user_id)}
                          </span>
                          <span className="text-sm text-[var(--color-text-muted)]">→</span>
                          <span className="text-sm font-medium text-[var(--color-text-primary)]">
                            {getUserDisplayName(session.target_user_id)}
                          </span>
                          {getStatusBadge(session)}
                        </div>
                        {session.reason && (
                          <p className="text-xs text-[var(--color-text-muted)] mt-1 truncate">
                            Reason: {session.reason}
                          </p>
                        )}
                      </div>
                    </div>

                    {/* Time Info */}
                    <div className="flex items-center gap-6 text-sm">
                      <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
                        <Calendar size={14} />
                        <span>{new Date(session.started_at).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
                        <Clock size={14} />
                        <span>{formatDuration(session.started_at, session.ended_at)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Session Details */}
                  <div className="mt-3 pt-3 border-t border-[var(--color-border-light)] text-xs text-[var(--color-text-muted)]">
                    <div className="flex flex-wrap gap-4">
                      <span>
                        Admin ID: <code className="font-mono">{session.admin_user_id.slice(0, 8)}...</code>
                      </span>
                      <span>
                        Target ID: <code className="font-mono">{session.target_user_id.slice(0, 8)}...</code>
                      </span>
                      <span>
                        Session ID: <code className="font-mono">{session.id.slice(0, 8)}...</code>
                      </span>
                      {session.ended_at && (
                        <span>
                          Ended: {new Date(session.ended_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Information Card */}
      <Card>
        <CardHeader>
          <CardTitle>About Impersonation</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-[var(--color-text-secondary)]">
            Impersonation allows administrators to temporarily access the system as another user 
            for support and troubleshooting purposes. All impersonation sessions are logged 
            and audited for security compliance.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

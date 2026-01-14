import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, Clock, Globe, Monitor } from 'lucide-react';
import { 
  Badge, 
  Button, 
  Card,
  CardContent,
  CardHeader,
  EmptyState,
} from '../../components/ui';
import { auditService } from '../../api/services';
import type { AuditLog } from '../../types';

export function UserAuditPage() {
  const [page, setPage] = useState(1);
  const pageSize = 20;

  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['user-audit-logs', page, pageSize],
    queryFn: () => auditService.listLogs({ 
      offset: (page - 1) * pageSize,
      limit: pageSize
    }),
  });

  const getEventColor = (type: string): 'success' | 'error' | 'warning' | 'default' => {
    if (type.includes('login') && type.includes('success')) return 'success';
    if (type.includes('fail') || type.includes('error') || type.includes('revoke')) return 'error';
    if (type.includes('update') || type.includes('change')) return 'warning';
    return 'default';
  };

  const formatEventType = (type: string) => {
    return type.split('.').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Activity Log</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          View security events and activity for your account.
        </p>
      </div>

      <Card>
        <CardHeader className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
            <ShieldAlert size={16} />
            <span>Secure Audit Trail</span>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center">
              <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-[var(--color-text-secondary)]">Loading logs...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon={<ShieldAlert size={32} />}
                title="No logs found"
                description="We haven't recorded any activity for your account yet."
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-surface-hover)]">
                    <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                      Event
                    </th>
                    <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                      IP Address
                    </th>
                    <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                      Device
                    </th>
                    <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                      Date & Time
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-light)]">
                  {logs.map((log: AuditLog) => (
                    <tr key={log.id} className="hover:bg-[var(--color-surface-hover)] transition-colors">
                      <td className="px-6 py-4">
                        <Badge variant={getEventColor(log.event_type)}>
                          {formatEventType(log.event_type)}
                        </Badge>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <Globe size={14} className="text-[var(--color-text-muted)]" />
                          <span className="font-mono text-xs text-[var(--color-text-secondary)]">
                            {log.ip || 'Unknown'}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <Monitor size={14} className="text-[var(--color-text-muted)]" />
                          <span className="text-sm text-[var(--color-text-primary)] truncate max-w-[200px]" title={log.user_agent || ''}>
                            {log.user_agent ? (
                              log.user_agent.includes('Mozilla') ? 'Browser' : 'Client'
                            ) : 'Unknown'}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <Clock size={14} className="text-[var(--color-text-muted)]" />
                          <div className="flex flex-col">
                            <span className="text-sm font-medium text-[var(--color-text-primary)]">
                              {new Date(log.created_at).toLocaleDateString()}
                            </span>
                            <span className="text-xs text-[var(--color-text-secondary)]">
                              {new Date(log.created_at).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          {logs.length > 0 && (
            <div className="p-4 border-t border-[var(--color-border-light)] flex items-center justify-between">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1 || isLoading}
              >
                Previous
              </Button>
              <span className="text-sm text-[var(--color-text-secondary)]">
                Page {page}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={logs.length < pageSize || isLoading}
              >
                Next
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

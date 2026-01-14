import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Search, 
  RefreshCw, 
  User,
  ChevronLeft,
  ChevronRight,
  Eye,
  Activity,
  Globe,
  Clock,
} from 'lucide-react';
import { auditService, userService } from '../../api/services';
import { 
  Button, 
  Card, 
  CardContent, 
  CardHeader,
  Badge, 
  Input, 
  Modal
} from '../../components/ui';
import type { AuditLog } from '../../types';

export function AdminAuditPage() {
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [isLogDetailOpen, setIsLogDetailOpen] = useState(false);
  const pageSize = 50;

  // Fetch all users for display
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: () => userService.list(),
  });

  // Fetch audit logs
  const { data: logs = [], isLoading, refetch } = useQuery({
    queryKey: ['admin-audit-logs', page, pageSize, eventTypeFilter],
    queryFn: () => auditService.listLogs({ 
      offset: (page - 1) * pageSize,
      limit: pageSize,
      event_type: eventTypeFilter !== 'all' ? eventTypeFilter : undefined,
    }),
  });

  const getUserEmail = (userId?: string) => {
    if (!userId) return 'System';
    const user = users.find(u => u.id === userId);
    return user?.email || userId.slice(0, 8) + '...';
  };

  const getEventTypeBadge = (eventType: string) => {
    const type = eventType.toLowerCase();
    if (type.includes('login') && type.includes('success')) return <Badge variant="success">LOGIN</Badge>;
    if (type.includes('login') && type.includes('fail')) return <Badge variant="error">LOGIN FAILED</Badge>;
    if (type.includes('create') || type.includes('register')) return <Badge variant="success">CREATE</Badge>;
    if (type.includes('update') || type.includes('change')) return <Badge variant="warning">UPDATE</Badge>;
    if (type.includes('delete') || type.includes('revoke')) return <Badge variant="error">DELETE</Badge>;
    if (type.includes('mfa')) return <Badge variant="default">MFA</Badge>;
    return <Badge variant="default">{eventType.toUpperCase()}</Badge>;
  };

  const filteredLogs = logs.filter((log) => {
    if (!searchQuery) return true;
    const searchLower = searchQuery.toLowerCase();
    return (
      log.event_type.toLowerCase().includes(searchLower) ||
      (log.user_id && getUserEmail(log.user_id).toLowerCase().includes(searchLower)) ||
      (log.ip && log.ip.toLowerCase().includes(searchLower))
    );
  });

  // Get unique event types for filter
  const eventTypes = Array.from(new Set(logs.map(log => log.event_type)));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">System Audit Logs</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">Track system activity and user actions</p>
        </div>
        <Button 
          variant="ghost" 
          leftIcon={<RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />} 
          onClick={() => refetch()}
        >
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between p-4 bg-[var(--color-surface-hover)] border-b border-[var(--color-border-light)]">
          <div className="flex items-center gap-4 flex-1">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" size={16} />
              <Input
                placeholder="Search logs by event, user, or IP..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                value={eventTypeFilter}
                onChange={(e) => setEventTypeFilter(e.target.value)}
                className="px-3 py-2 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
              >
                <option value="all">All Events</option>
                {eventTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="text-xs text-[var(--color-text-muted)] ml-4">
            {filteredLogs.length} records
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-[var(--color-surface-hover)] text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-3">Timestamp</th>
                  <th className="px-6 py-3">User</th>
                  <th className="px-6 py-3">Event Type</th>
                  <th className="px-6 py-3">IP Address</th>
                  <th className="px-6 py-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-light)]">
                {isLoading && logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin" />
                        <p className="text-[var(--color-text-secondary)]">Loading logs...</p>
                      </div>
                    </td>
                  </tr>
                ) : filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <Activity size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
                      <p className="text-[var(--color-text-secondary)]">No logs found</p>
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-[var(--color-surface-hover)] transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <Clock size={14} className="text-[var(--color-text-muted)]" />
                          <div className="flex flex-col">
                            <span className="text-xs font-medium text-[var(--color-text-primary)] font-mono whitespace-nowrap">
                              {new Date(log.created_at).toLocaleDateString()}
                            </span>
                            <span className="text-xs text-[var(--color-text-secondary)] font-mono">
                              {new Date(log.created_at).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <User size={14} className="text-[var(--color-text-muted)]" />
                          <span className="text-sm font-medium text-[var(--color-text-primary)] truncate max-w-[200px]" title={getUserEmail(log.user_id)}>
                            {getUserEmail(log.user_id)}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4">{getEventTypeBadge(log.event_type)}</td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <Globe size={14} className="text-[var(--color-text-muted)]" />
                          <span className="text-[var(--color-text-secondary)] font-mono text-xs">
                            {log.ip || 'N/A'}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button 
                          onClick={() => { setSelectedLog(log); setIsLogDetailOpen(true); }}
                          className="p-2 text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-hover)] rounded-lg transition-colors"
                          title="View Details"
                        >
                          <Eye size={18} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
        {logs.length > 0 && (
          <div className="p-4 border-t border-[var(--color-border-light)] flex items-center justify-between bg-[var(--color-surface-hover)]/30">
            <Button 
              variant="ghost" 
              size="sm" 
              disabled={page === 1} 
              onClick={() => setPage(p => p - 1)}
              leftIcon={<ChevronLeft size={16} />}
            >
              Previous
            </Button>
            <div className="text-sm text-[var(--color-text-muted)]">Page {page}</div>
            <Button 
              variant="ghost" 
              size="sm" 
              disabled={logs.length < pageSize} 
              onClick={() => setPage(p => p + 1)}
              rightIcon={<ChevronRight size={16} />}
            >
              Next
            </Button>
          </div>
        )}
      </Card>

      {/* Log Detail Modal */}
      <Modal isOpen={isLogDetailOpen} onClose={() => setIsLogDetailOpen(false)} title="Audit Log Details" size="lg">
        {selectedLog && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">Event Type</label>
                <div className="mt-1">{getEventTypeBadge(selectedLog.event_type)}</div>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">Timestamp</label>
                <div className="mt-1 text-sm text-[var(--color-text-secondary)]">{new Date(selectedLog.created_at).toLocaleString()}</div>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">User</label>
                <div className="mt-1 text-sm text-[var(--color-text-primary)] font-medium">{getUserEmail(selectedLog.user_id)}</div>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">Actor</label>
                <div className="mt-1 text-sm text-[var(--color-text-primary)] font-medium">{selectedLog.actor_id ? getUserEmail(selectedLog.actor_id) : 'N/A'}</div>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">IP Address</label>
                <div className="mt-1 text-sm text-[var(--color-text-secondary)] font-mono">{selectedLog.ip || 'N/A'}</div>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">Tenant ID</label>
                <div className="mt-1 text-sm text-[var(--color-text-secondary)] font-mono">{selectedLog.tenant_id || 'N/A'}</div>
              </div>
            </div>
            {selectedLog.data && Object.keys(selectedLog.data).length > 0 && (
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">Event Data</label>
                <div className="mt-1 p-3 bg-[var(--color-surface-hover)] rounded-lg border border-[var(--color-border-light)] text-sm font-mono text-[var(--color-text-secondary)] overflow-x-auto max-h-64 overflow-y-auto">
                  <pre>{JSON.stringify(selectedLog.data, null, 2)}</pre>
                </div>
              </div>
            )}
            {selectedLog.user_agent && (
              <div>
                <label className="text-xs font-medium text-[var(--color-text-muted)] uppercase">User Agent</label>
                <div className="mt-1 text-xs text-[var(--color-text-muted)] italic break-all">{selectedLog.user_agent}</div>
              </div>
            )}
            <div className="flex justify-end pt-4">
              <Button variant="primary" onClick={() => setIsLogDetailOpen(false)}>Close</Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Mail, Send, CheckCircle, Eye, MousePointer, AlertTriangle, XCircle,
  TrendingUp, BarChart3, Ban
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, LoadingBar, Badge } from '../../components/ui';
import { adminService } from '../../api/services';
import type { EmailStats, EmailBounce, EmailSuppression } from '../../types';

export function AdminEmailAnalyticsPage() {
  const [days, setDays] = useState(30);
  const [activeTab, setActiveTab] = useState<'stats' | 'bounces' | 'suppressions'>('stats');

  // Fetch email stats
  const { data: stats, isLoading: statsLoading } = useQuery<EmailStats>({
    queryKey: ['email-stats', days],
    queryFn: () => adminService.getEmailStats(days),
  });

  // Fetch bounces
  const { data: bounces = [], isLoading: bouncesLoading } = useQuery<EmailBounce[]>({
    queryKey: ['email-bounces'],
    queryFn: () => adminService.listEmailBounces(),
    enabled: activeTab === 'bounces',
  });

  // Fetch suppressions
  const { data: suppressions = [], isLoading: suppressionsLoading } = useQuery<EmailSuppression[]>({
    queryKey: ['email-suppressions'],
    queryFn: () => adminService.listEmailSuppressions(),
    enabled: activeTab === 'suppressions',
  });

  const deliveryRate = stats && stats.total_sent > 0 
    ? ((stats.total_delivered / stats.total_sent) * 100).toFixed(1) 
    : '0';

  const openRate = stats && stats.total_delivered > 0 
    ? ((stats.total_opened / stats.total_delivered) * 100).toFixed(1) 
    : '0';

  const clickRate = stats && stats.total_opened > 0 
    ? ((stats.total_clicked / stats.total_opened) * 100).toFixed(1) 
    : '0';

  const bounceRate = stats && stats.total_sent > 0 
    ? ((stats.total_bounced / stats.total_sent) * 100).toFixed(1) 
    : '0';

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={statsLoading} message="Loading email analytics..." />

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Email Analytics</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Monitor email delivery, engagement, and health metrics.
          </p>
        </div>
        <div className="flex gap-2">
          {[7, 30, 90].map((d) => (
            <Button
              key={d}
              variant={days === d ? 'primary' : 'outline'}
              size="sm"
              onClick={() => setDays(d)}
            >
              {d} Days
            </Button>
          ))}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Emails Sent</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {stats?.total_sent.toLocaleString() || 0}
                </p>
              </div>
              <div className="p-3 rounded-full bg-blue-500/10">
                <Send size={24} className="text-blue-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Delivered</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {stats?.total_delivered.toLocaleString() || 0}
                </p>
                <p className="text-xs text-green-500 mt-1">{deliveryRate}% rate</p>
              </div>
              <div className="p-3 rounded-full bg-green-500/10">
                <CheckCircle size={24} className="text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Opened</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {stats?.total_opened.toLocaleString() || 0}
                </p>
                <p className="text-xs text-blue-500 mt-1">{openRate}% rate</p>
              </div>
              <div className="p-3 rounded-full bg-purple-500/10">
                <Eye size={24} className="text-purple-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Clicked</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {stats?.total_clicked.toLocaleString() || 0}
                </p>
                <p className="text-xs text-orange-500 mt-1">{clickRate}% rate</p>
              </div>
              <div className="p-3 rounded-full bg-orange-500/10">
                <MousePointer size={24} className="text-orange-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Bounced</p>
                <p className="text-2xl font-bold text-red-400 mt-1">
                  {stats?.total_bounced.toLocaleString() || 0}
                </p>
                <p className="text-xs text-red-400 mt-1">{bounceRate}% rate</p>
              </div>
              <div className="p-3 rounded-full bg-red-500/10">
                <AlertTriangle size={24} className="text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Dropped</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {stats?.total_dropped.toLocaleString() || 0}
                </p>
              </div>
              <div className="p-3 rounded-full bg-gray-500/10">
                <XCircle size={24} className="text-gray-500" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--color-text-secondary)]">Suppressed</p>
                <p className="text-2xl font-bold text-[var(--color-text-primary)] mt-1">
                  {suppressions.length.toLocaleString()}
                </p>
              </div>
              <div className="p-3 rounded-full bg-yellow-500/10">
                <Ban size={24} className="text-yellow-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-2">
        <Button
          variant={activeTab === 'stats' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('stats')}
        >
          <BarChart3 size={16} className="mr-2" />
          By Template
        </Button>
        <Button
          variant={activeTab === 'bounces' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('bounces')}
        >
          <AlertTriangle size={16} className="mr-2" />
          Bounces
        </Button>
        <Button
          variant={activeTab === 'suppressions' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('suppressions')}
        >
          <Ban size={16} className="mr-2" />
          Suppressions
        </Button>
      </div>

      {/* Tab Content */}
      {activeTab === 'stats' && stats?.by_template && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp size={18} />
              Emails by Template Type
            </CardTitle>
          </CardHeader>
          <CardContent>
            {Object.keys(stats.by_template).length === 0 ? (
              <p className="text-center text-[var(--color-text-secondary)] py-8">
                No email data for this period.
              </p>
            ) : (
              <div className="space-y-3">
                {Object.entries(stats.by_template)
                  .sort(([, a], [, b]) => b - a)
                  .map(([template, count]) => (
                    <div key={template} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Mail size={16} className="text-[var(--color-primary)]" />
                        <span className="text-[var(--color-text-primary)] capitalize">
                          {template.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-32 h-2 rounded-full bg-[var(--color-surface-hover)] overflow-hidden">
                          <div 
                            className="h-full bg-[var(--color-primary)] rounded-full"
                            style={{ width: `${(count / stats.total_sent) * 100}%` }}
                          />
                        </div>
                        <span className="text-sm text-[var(--color-text-secondary)] w-16 text-right">
                          {count.toLocaleString()}
                        </span>
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'bounces' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle size={18} />
              Recent Bounces
            </CardTitle>
          </CardHeader>
          <CardContent>
            <LoadingBar isLoading={bouncesLoading} message="Loading bounces..." />
            {!bouncesLoading && bounces.length === 0 ? (
              <p className="text-center text-[var(--color-text-secondary)] py-8">
                No bounces recorded.
              </p>
            ) : (
              <div className="space-y-2">
                {bounces.slice(0, 50).map((bounce) => (
                  <div 
                    key={bounce.id}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)]"
                  >
                    <div>
                      <p className="text-[var(--color-text-primary)]">{bounce.email}</p>
                      <p className="text-xs text-[var(--color-text-muted)]">
                        {bounce.error_message || 'No details'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge 
                        variant={bounce.bounce_type === 'hard' ? 'error' : 'warning'}
                        size="sm"
                      >
                        {bounce.bounce_type}
                      </Badge>
                      <span className="text-xs text-[var(--color-text-muted)]">
                        {new Date(bounce.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'suppressions' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Ban size={18} />
              Suppression List
            </CardTitle>
          </CardHeader>
          <CardContent>
            <LoadingBar isLoading={suppressionsLoading} message="Loading suppressions..." />
            {!suppressionsLoading && suppressions.length === 0 ? (
              <p className="text-center text-[var(--color-text-secondary)] py-8">
                No suppressed emails.
              </p>
            ) : (
              <div className="space-y-2">
                {suppressions.slice(0, 50).map((suppression) => (
                  <div 
                    key={suppression.id}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)]"
                  >
                    <div>
                      <p className="text-[var(--color-text-primary)]">{suppression.email}</p>
                      <p className="text-xs text-[var(--color-text-muted)]">
                        Source: {suppression.source || 'Unknown'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="warning" size="sm">
                        {suppression.reason.replace(/_/g, ' ')}
                      </Badge>
                      <span className="text-xs text-[var(--color-text-muted)]">
                        {new Date(suppression.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

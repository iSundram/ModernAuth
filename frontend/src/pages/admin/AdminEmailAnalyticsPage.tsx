import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Mail, Send, CheckCircle, Eye, MousePointer, AlertTriangle, XCircle,
  TrendingUp, BarChart3, Ban, Download, RefreshCw, ArrowUpRight, Plus
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, LoadingBar, Badge, Select, Input, Modal } from '../../components/ui';
import { useToast } from '../../components/ui/Toast';
import { adminService } from '../../api/services';
import type { EmailStats, EmailBounce, EmailSuppression, EmailABTest } from '../../types';

interface DailyData {
  date: string;
  sent: number;
  delivered: number;
  opened: number;
  clicked: number;
  bounced: number;
}

export function AdminEmailAnalyticsPage() {
  const [days, setDays] = useState(30);
  const [activeTab, setActiveTab] = useState<'stats' | 'bounces' | 'suppressions' | 'abtests'>('stats');
  const [compareTemplates, setCompareTemplates] = useState<string[]>([]);
  const [exportFormat, setExportFormat] = useState<'csv' | 'json'>('csv');
  const [showCreateTestModal, setShowCreateTestModal] = useState(false);
  const [newTest, setNewTest] = useState({
    name: '',
    template_type: 'welcome',
    variant_a: 'Original Subject Line',
    variant_b: 'Alternative Subject Line',
    weight_a: 50,
    weight_b: 50,
  });

  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery<EmailStats>({
    queryKey: ['email-stats', days],
    queryFn: () => adminService.getEmailStats(days),
  });

  const { data: bounces = [], isLoading: bouncesLoading } = useQuery<EmailBounce[]>({
    queryKey: ['email-bounces'],
    queryFn: () => adminService.listEmailBounces(),
    enabled: activeTab === 'bounces',
  });

  const { data: suppressions = [], isLoading: suppressionsLoading } = useQuery<EmailSuppression[]>({
    queryKey: ['email-suppressions'],
    queryFn: () => adminService.listEmailSuppressions(),
    enabled: activeTab === 'suppressions',
  });

  const { data: abTests = [], isLoading: abTestsLoading } = useQuery<EmailABTest[]>({
    queryKey: ['email-abtests'],
    queryFn: () => adminService.listEmailABTests(),
    enabled: activeTab === 'abtests',
  });

  // Mutation for creating A/B tests
  const createABTestMutation = useMutation({
    mutationFn: () => adminService.createEmailABTest({
      name: newTest.name,
      template_type: newTest.template_type,
      variant_a: newTest.variant_a,
      variant_b: newTest.variant_b,
      weight_a: newTest.weight_a,
      weight_b: newTest.weight_b,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-abtests'] });
      setShowCreateTestModal(false);
      setNewTest({
        name: '',
        template_type: 'welcome',
        variant_a: 'Original Subject Line',
        variant_b: 'Alternative Subject Line',
        weight_a: 50,
        weight_b: 50,
      });
      showToast({ title: 'Success', message: 'A/B test created successfully', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create A/B test', type: 'error' });
    },
  });

  const handleCreateTest = () => {
    if (!newTest.name.trim()) {
      showToast({ title: 'Error', message: 'Please enter a test name', type: 'error' });
      return;
    }
    createABTestMutation.mutate();
  };

  // Note: by_day only contains sent counts from the API
  // For a real implementation, the backend should return daily breakdowns
  // for all metrics (delivered, opened, clicked, bounced)
  const dailyData: DailyData[] = useMemo(() => {
    if (!stats?.by_day) return [];
    return Object.entries(stats.by_day)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, sent]) => ({
        date,
        sent,
        // TODO: Backend should provide daily breakdowns for these metrics
        // Currently showing sent only in the chart
        delivered: 0,
        opened: 0,
        clicked: 0,
        bounced: 0,
      }));
  }, [stats?.by_day]);

  const maxDailyValue = Math.max(...dailyData.map(d => d.sent), 1);

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

  const handleExport = async () => {
    try {
      const data = await adminService.exportEmailAnalytics(exportFormat);
      const blob = data as Blob;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `email-analytics-${new Date().toISOString().split('T')[0]}.${exportFormat}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export analytics:', error);
    }
  };

  const templateOptions = Object.keys(stats?.by_template || {}).map(t => ({
    value: t,
    label: t.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
  }));

  const toggleTemplateComparison = (template: string) => {
    setCompareTemplates(prev => 
      prev.includes(template) 
        ? prev.filter(t => t !== template)
        : [...prev, template]
    );
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={statsLoading} message="Loading email analytics..." />

      {/* Header Actions */}
      <div className="flex items-center justify-between flex-wrap gap-4">
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
        <div className="flex gap-2 items-center">
          <Select 
            value={exportFormat} 
            onChange={(e) => setExportFormat(e.target.value as 'csv' | 'json')}
            options={[
              { value: 'csv', label: 'CSV' },
              { value: 'json', label: 'JSON' }
            ]}
            className="w-32"
          />
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download size={16} className="mr-2" />
            Export
          </Button>
          <Button variant="ghost" size="sm" onClick={() => refetchStats()}>
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Trend Chart */}
      {dailyData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp size={18} />
              Email Trends Over Time
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-48 flex items-end gap-1">
              {dailyData.map((day, idx) => {
                const height = (day.sent / maxDailyValue) * 100;
                const isToday = idx === dailyData.length - 1;
                return (
                  <div
                    key={day.date}
                    className="flex-1 flex flex-col items-center group relative"
                  >
                    <div
                      className={`w-full rounded-t transition-all hover:opacity-80 ${isToday ? 'bg-[var(--color-primary)]' : 'bg-[var(--color-surface-hover)]'}`}
                      style={{ height: `${Math.max(height, 2)}%` }}
                    />
                    <div className="absolute bottom-full mb-2 hidden group-hover:block z-10">
                      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] p-2 rounded text-xs shadow-lg whitespace-nowrap">
                        <div className="font-medium">{day.date}</div>
                        <div className="text-[var(--color-text-muted)]">
                          Sent: {day.sent.toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between text-xs text-[var(--color-text-muted)] mt-2">
              <span>{dailyData[0]?.date}</span>
              <span>{dailyData[dailyData.length - 1]?.date}</span>
            </div>
          </CardContent>
        </Card>
      )}

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
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-2 flex-wrap">
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
        <Button
          variant={activeTab === 'abtests' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('abtests')}
        >
          <TrendingUp size={16} className="mr-2" />
          A/B Tests
        </Button>
      </div>

      {/* Template Comparison */}
      {activeTab === 'stats' && templateOptions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Mail size={18} />
                Template Comparison
              </span>
              <Select 
                value="" 
                onChange={(e) => e.target.value && toggleTemplateComparison(e.target.value)}
                options={templateOptions.map(opt => ({
                  value: opt.value,
                  label: (compareTemplates.includes(opt.value) ? '✓ ' : '') + opt.label
                }))}
                placeholder="Add template to compare"
                className="w-48"
              />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templateOptions.slice(0, 6).map(opt => {
                const count = stats?.by_template[opt.value] || 0;
                const percentage = stats?.total_sent ? ((count / stats.total_sent) * 100).toFixed(1) : '0';
                const isSelected = compareTemplates.includes(opt.value);
                return (
                  <div
                    key={opt.value}
                    className={`p-4 rounded-lg border cursor-pointer transition-all ${
                      isSelected 
                        ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/5' 
                        : 'border-[var(--color-border)] hover:border-[var(--color-primary)]'
                    }`}
                    onClick={() => toggleTemplateComparison(opt.value)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{opt.label}</span>
                      {isSelected && <CheckCircle size={16} className="text-[var(--color-primary)]" />}
                    </div>
                    <div className="text-2xl font-bold">{count.toLocaleString()}</div>
                    <div className="text-sm text-[var(--color-text-muted)]">{percentage}% of total</div>
                    <div className="mt-2 h-2 rounded-full bg-[var(--color-surface-hover)] overflow-hidden">
                      <div
                        className="h-full bg-[var(--color-primary)] rounded-full transition-all"
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

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

      {/* A/B Tests Tab */}
      {activeTab === 'abtests' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <TrendingUp size={18} />
                A/B Tests
              </span>
              <Button size="sm" onClick={() => setShowCreateTestModal(true)}>
                <Plus size={16} className="mr-2" />
                Create Test
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <LoadingBar isLoading={abTestsLoading} message="Loading A/B tests..." />
            {!abTestsLoading && abTests.length === 0 ? (
              <div className="text-center py-12">
                <TrendingUp size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
                <h3 className="text-lg font-medium mb-2">No A/B Tests Yet</h3>
                <p className="text-[var(--color-text-secondary)] mb-4">
                  Create your first A/B test to optimize email engagement.
                </p>
                <Button onClick={() => setShowCreateTestModal(true)}>Create A/B Test</Button>
              </div>
            ) : (
              <div className="space-y-4">
                {abTests.map((test) => (
                  <div
                    key={test.id}
                    className="p-4 rounded-lg border border-[var(--color-border)]"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h4 className="font-medium">{test.name}</h4>
                        <p className="text-sm text-[var(--color-text-muted)]">
                          {test.template_type.replace(/_/g, ' ')} • Started {test.start_date}
                        </p>
                      </div>
                      <Badge variant={test.is_active ? 'success' : 'default'}>
                        {test.is_active ? 'Active' : 'Completed'}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-3 rounded bg-[var(--color-surface-hover)]">
                        <div className="text-sm text-[var(--color-text-muted)] mb-1">Variant A</div>
                        <div className="font-medium">{test.variant_a}</div>
                        <div className="text-xs text-[var(--color-text-muted)]">
                          Weight: {test.weight_a}%
                        </div>
                      </div>
                      <div className="p-3 rounded bg-[var(--color-surface-hover)]">
                        <div className="text-sm text-[var(--color-text-muted)] mb-1">Variant B</div>
                        <div className="font-medium">{test.variant_b}</div>
                        <div className="text-xs text-[var(--color-text-muted)]">
                          Weight: {test.weight_b}%
                        </div>
                      </div>
                    </div>
                    {test.winner_variant && (
                      <div className="mt-4 p-3 rounded bg-green-500/10 text-green-500 flex items-center gap-2">
                        <ArrowUpRight size={16} />
                        Winner: Variant {test.winner_variant.toUpperCase()}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Create A/B Test Modal */}
      <Modal
        isOpen={showCreateTestModal}
        onClose={() => setShowCreateTestModal(false)}
        title="Create A/B Test"
      >
        <div className="space-y-4">
          <Input
            label="Test Name"
            value={newTest.name}
            onChange={(e) => setNewTest(prev => ({ ...prev, name: e.target.value }))}
            placeholder="e.g., Welcome Email Subject Test"
          />

          <Select
            label="Template Type"
            value={newTest.template_type}
            onChange={(e) => setNewTest(prev => ({ ...prev, template_type: e.target.value }))}
            options={[
              { value: 'welcome', label: 'Welcome Email' },
              { value: 'verification', label: 'Email Verification' },
              { value: 'password_reset', label: 'Password Reset' },
              { value: 'password_changed', label: 'Password Changed' },
              { value: 'login_alert', label: 'Login Alert' },
              { value: 'invitation', label: 'Invitation' },
              { value: 'mfa_enabled', label: 'MFA Enabled' },
            ]}
          />

          <Input
            label="Variant A (Control)"
            value={newTest.variant_a}
            onChange={(e) => setNewTest(prev => ({ ...prev, variant_a: e.target.value }))}
            placeholder="Original subject line or template variation"
          />

          <Input
            label="Variant B (Treatment)"
            value={newTest.variant_b}
            onChange={(e) => setNewTest(prev => ({ ...prev, variant_b: e.target.value }))}
            placeholder="Alternative subject line or template variation"
          />

          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Variant A Weight (%)"
              type="number"
              value={newTest.weight_a}
              onChange={(e) => {
                const val = parseInt(e.target.value) || 0;
                setNewTest(prev => ({ ...prev, weight_a: val, weight_b: 100 - val }));
              }}
              min={0}
              max={100}
            />
            <Input
              label="Variant B Weight (%)"
              type="number"
              value={newTest.weight_b}
              onChange={(e) => {
                const val = parseInt(e.target.value) || 0;
                setNewTest(prev => ({ ...prev, weight_b: val, weight_a: 100 - val }));
              }}
              min={0}
              max={100}
            />
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <Button variant="outline" onClick={() => setShowCreateTestModal(false)}>
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleCreateTest}
              isLoading={createABTestMutation.isPending}
            >
              Create Test
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

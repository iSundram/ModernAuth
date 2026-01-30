import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Building2,
  Key,
  Shield,
  Globe,
  Users,
  Download,
  Copy,
  Trash2,
  Plus,
  Check,
  AlertCircle,
  Pause,
  Play,
  Upload,
  Settings,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Badge, Modal, Input, ConfirmDialog } from '../../components/ui';
import { tenantService } from '../../api/services';
import { useToast } from '../../components/ui/Toast';
import type { TenantAPIKey, TenantFeatures } from '../../types';

export function TenantDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  
  const [activeTab, setActiveTab] = useState<'overview' | 'api-keys' | 'features' | 'domain' | 'import'>('overview');
  const [showCreateKeyModal, setShowCreateKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [importData, setImportData] = useState('');
  const [keyToDelete, setKeyToDelete] = useState<string | null>(null);

  // Fetch tenant
  const { data: tenant, isLoading } = useQuery({
    queryKey: ['tenant', id],
    queryFn: () => tenantService.get(id!),
    enabled: !!id,
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['tenant-stats', id],
    queryFn: () => tenantService.getStats(id!),
    enabled: !!id,
  });

  // Fetch API keys
  const { data: apiKeysData } = useQuery({
    queryKey: ['tenant-api-keys', id],
    queryFn: () => tenantService.listAPIKeys(id!),
    enabled: !!id && activeTab === 'api-keys',
  });
  const apiKeys: TenantAPIKey[] = apiKeysData?.data || [];

  // Fetch features
  const { data: features } = useQuery({
    queryKey: ['tenant-features', id],
    queryFn: () => tenantService.getFeatures(id!),
    enabled: !!id && activeTab === 'features',
  });

  // Fetch domain verification
  const { data: domainStatus, refetch: refetchDomain } = useQuery({
    queryKey: ['tenant-domain', id],
    queryFn: () => tenantService.checkDomainVerification(id!),
    enabled: !!id && activeTab === 'domain' && !!tenant?.domain,
  });

  // Mutations
  const suspendMutation = useMutation({
    mutationFn: () => tenantService.suspend(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant', id] });
      showToast({ title: 'Success', type: 'success', message: 'Tenant suspended' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to suspend tenant' }),
  });

  const activateMutation = useMutation({
    mutationFn: () => tenantService.activate(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant', id] });
      showToast({ title: 'Success', type: 'success', message: 'Tenant activated' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to activate tenant' }),
  });

  const createKeyMutation = useMutation({
    mutationFn: (name: string) => tenantService.createAPIKey(id!, { name }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tenant-api-keys', id] });
      setCreatedKey(data.key);
      setNewKeyName('');
      showToast({ title: 'Success', type: 'success', message: 'API key created' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to create API key' }),
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (keyId: string) => tenantService.revokeAPIKey(id!, keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-api-keys', id] });
      setKeyToDelete(null);
      showToast({ title: 'Success', type: 'success', message: 'API key revoked' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to revoke API key' }),
  });

  const updateFeaturesMutation = useMutation({
    mutationFn: (updates: Partial<TenantFeatures>) => tenantService.updateFeatures(id!, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-features', id] });
      showToast({ title: 'Success', type: 'success', message: 'Features updated' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to update features' }),
  });

  const initDomainMutation = useMutation({
    mutationFn: () => tenantService.initiateDomainVerification(id!),
    onSuccess: () => {
      refetchDomain();
      showToast({ title: 'Success', type: 'success', message: 'Domain verification initiated' });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to initiate verification' }),
  });

  const bulkImportMutation = useMutation({
    mutationFn: (users: Array<{ email: string; first_name?: string; last_name?: string }>) =>
      tenantService.bulkImportUsers(id!, users),
    onSuccess: (result) => {
      setImportData('');
      showToast({ 
        title: result.failed > 0 ? 'Warning' : 'Success', 
        type: result.failed > 0 ? 'warning' : 'success', 
        message: `Imported ${result.succeeded}/${result.total} users` 
      });
    },
    onError: () => showToast({ title: 'Error', type: 'error', message: 'Failed to import users' }),
  });

  const handleExportAudit = async (format: 'json' | 'csv') => {
    try {
      const blob = await tenantService.exportAuditLogs(id!, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_logs.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      showToast({ title: 'Success', type: 'success', message: 'Audit logs exported' });
    } catch {
      showToast({ title: 'Error', type: 'error', message: 'Failed to export audit logs' });
    }
  };

  const handleBulkImport = () => {
    try {
      const lines = importData.trim().split('\n');
      const users = lines.map(line => {
        const [email, first_name, last_name] = line.split(',').map(s => s.trim());
        return { email, first_name: first_name || undefined, last_name: last_name || undefined };
      });
      bulkImportMutation.mutate(users);
    } catch {
      showToast({ title: 'Error', type: 'error', message: 'Invalid import format' });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    showToast({ title: 'Copied', type: 'success', message: 'Copied to clipboard' });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[var(--color-primary)]" />
      </div>
    );
  }

  if (!tenant) {
    return (
      <div className="text-center py-12">
        <p className="text-[var(--color-text-muted)]">Tenant not found</p>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Building2 },
    { id: 'api-keys', label: 'API Keys', icon: Key },
    { id: 'features', label: 'Features', icon: Settings },
    { id: 'domain', label: 'Domain', icon: Globe },
    { id: 'import', label: 'Import', icon: Upload },
  ] as const;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={() => navigate('/admin/tenants')}>
            <ArrowLeft size={16} />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">{tenant.name}</h1>
              <Badge variant={tenant.is_active ? 'success' : 'error'}>
                {tenant.is_active ? 'Active' : 'Suspended'}
              </Badge>
            </div>
            <p className="text-[var(--color-text-muted)] text-sm">{tenant.slug}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {tenant.is_active ? (
            <Button
              variant="outline"
              onClick={() => suspendMutation.mutate()}
              isLoading={suspendMutation.isPending}
              leftIcon={<Pause size={16} />}
            >
              Suspend
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={() => activateMutation.mutate()}
              isLoading={activateMutation.isPending}
              leftIcon={<Play size={16} />}
            >
              Activate
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-[var(--color-primary)] text-[var(--color-primary)]'
                : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
            }`}
          >
            <tab.icon size={16} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users size={18} />
                Users
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold">{stats?.user_count || 0}</p>
              <p className="text-sm text-[var(--color-text-muted)]">
                {stats?.max_users ? `of ${stats.max_users} max` : 'Unlimited'}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield size={18} />
                Plan
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold capitalize">{stats?.plan || tenant.plan || 'Free'}</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download size={18} />
                Export Audit Logs
              </CardTitle>
            </CardHeader>
            <CardContent className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => handleExportAudit('json')}>
                JSON
              </Button>
              <Button variant="outline" size="sm" onClick={() => handleExportAudit('csv')}>
                CSV
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'api-keys' && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Key size={18} />
              API Keys
            </CardTitle>
            <Button size="sm" onClick={() => setShowCreateKeyModal(true)} leftIcon={<Plus size={14} />}>
              Create Key
            </Button>
          </CardHeader>
          <CardContent>
            {apiKeys.length === 0 ? (
              <p className="text-[var(--color-text-muted)] text-center py-8">No API keys created yet</p>
            ) : (
              <div className="space-y-3">
                {apiKeys.map(key => (
                  <div
                    key={key.id}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)]"
                  >
                    <div>
                      <p className="font-medium text-[var(--color-text-primary)]">{key.name}</p>
                      <p className="text-sm text-[var(--color-text-muted)]">{key.key_prefix}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {key.expires_at && (
                        <span className="text-xs text-[var(--color-text-muted)]">
                          Expires: {new Date(key.expires_at).toLocaleDateString()}
                        </span>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setKeyToDelete(key.id)}
                        className="text-red-500 hover:bg-red-500/10"
                      >
                        <Trash2 size={14} />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'features' && features && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings size={18} />
              Feature Flags
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { key: 'sso_enabled', label: 'SSO Enabled', desc: 'Allow single sign-on authentication' },
              { key: 'api_access_enabled', label: 'API Access', desc: 'Allow API key authentication' },
              { key: 'webhooks_enabled', label: 'Webhooks', desc: 'Enable webhook notifications' },
              { key: 'mfa_required', label: 'MFA Required', desc: 'Require MFA for all users' },
              { key: 'custom_branding', label: 'Custom Branding', desc: 'Allow custom branding' },
            ].map(({ key, label, desc }) => (
              <div key={key} className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)]">
                <div>
                  <p className="font-medium text-[var(--color-text-primary)]">{label}</p>
                  <p className="text-sm text-[var(--color-text-muted)]">{desc}</p>
                </div>
                <button
                  onClick={() => updateFeaturesMutation.mutate({ [key]: !features[key as keyof TenantFeatures] })}
                  className={`relative w-12 h-6 rounded-full transition-colors ${
                    features[key as keyof TenantFeatures] ? 'bg-green-500' : 'bg-[var(--color-border)]'
                  }`}
                >
                  <span
                    className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
                      features[key as keyof TenantFeatures] ? 'left-7' : 'left-1'
                    }`}
                  />
                </button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {activeTab === 'domain' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe size={18} />
              Domain Verification
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!tenant.domain ? (
              <p className="text-[var(--color-text-muted)]">No domain configured for this tenant</p>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{tenant.domain}</span>
                  {domainStatus?.status === 'verified' ? (
                    <Badge variant="success" className="flex items-center gap-1">
                      <Check size={12} /> Verified
                    </Badge>
                  ) : (
                    <Badge variant="warning" className="flex items-center gap-1">
                      <AlertCircle size={12} /> Pending
                    </Badge>
                  )}
                </div>

                {domainStatus && domainStatus.status !== 'verified' && (
                  <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] space-y-3">
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Add this TXT record to your DNS settings:
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 p-2 rounded bg-[var(--color-surface)] text-sm">
                        _modernauth.{tenant.domain} TXT &quot;{domainStatus.txt_record}&quot;
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(domainStatus.txt_record)}
                      >
                        <Copy size={14} />
                      </Button>
                    </div>
                    <Button variant="outline" onClick={() => refetchDomain()} size="sm">
                      Check Status
                    </Button>
                  </div>
                )}

                {!domainStatus && (
                  <Button onClick={() => initDomainMutation.mutate()} isLoading={initDomainMutation.isPending}>
                    Start Verification
                  </Button>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === 'import' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Upload size={18} />
              Bulk Import Users
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-[var(--color-text-secondary)]">
              Import multiple users at once. Format: email,first_name,last_name (one per line)
            </p>
            <textarea
              value={importData}
              onChange={e => setImportData(e.target.value)}
              placeholder={"john@example.com,John,Doe\njane@example.com,Jane,Smith"}
              className="w-full h-40 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] font-mono text-sm"
            />
            <Button
              onClick={handleBulkImport}
              isLoading={bulkImportMutation.isPending}
              disabled={!importData.trim()}
            >
              Import Users
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Create API Key Modal */}
      <Modal
        isOpen={showCreateKeyModal}
        onClose={() => {
          setShowCreateKeyModal(false);
          setCreatedKey(null);
          setNewKeyName('');
        }}
        title={createdKey ? 'API Key Created' : 'Create API Key'}
      >
        {createdKey ? (
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <p className="text-sm text-yellow-500 font-medium mb-2">
                Save this key now! It won&apos;t be shown again.
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-2 rounded bg-[var(--color-surface)] text-sm break-all">
                  {createdKey}
                </code>
                <Button variant="ghost" size="sm" onClick={() => copyToClipboard(createdKey)}>
                  <Copy size={14} />
                </Button>
              </div>
            </div>
            <Button onClick={() => { setShowCreateKeyModal(false); setCreatedKey(null); }} className="w-full">
              Done
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <Input
              label="Key Name"
              value={newKeyName}
              onChange={e => setNewKeyName(e.target.value)}
              placeholder="e.g., Production API"
            />
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" onClick={() => setShowCreateKeyModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createKeyMutation.mutate(newKeyName)}
                isLoading={createKeyMutation.isPending}
                disabled={!newKeyName.trim()}
              >
                Create
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete Key Confirmation */}
      <ConfirmDialog
        isOpen={!!keyToDelete}
        onClose={() => setKeyToDelete(null)}
        onConfirm={() => keyToDelete && revokeKeyMutation.mutate(keyToDelete)}
        title="Revoke API Key"
        message="Are you sure you want to revoke this API key? Any integrations using it will stop working."
      />
    </div>
  );
}

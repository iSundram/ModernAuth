import { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  Search,
  Edit,
  Trash2,
  RefreshCw,
  Key,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  EyeOff,
} from 'lucide-react';
import { Button, Input, Card, CardContent, CardHeader, Modal, useToast } from '../../components/ui';
import { scimAdminService, type ScimProvider, type ScimSyncLog } from '../../api/services';

const ProviderTypeBadge = ({ type }: { type: ScimProvider['type'] }) => {
  const labels: Record<ScimProvider['type'], string> = {
    okta: 'Okta',
    azure_ad: 'Azure AD',
    onelogin: 'OneLogin',
    generic: 'Generic SCIM',
  };

  const colors: Record<ScimProvider['type'], string> = {
    okta: 'bg-blue-500/10 text-blue-600 border-blue-500/20',
    azure_ad: 'bg-purple-500/10 text-purple-600 border-purple-500/20',
    onelogin: 'bg-orange-500/10 text-orange-600 border-orange-500/20',
    generic: 'bg-gray-500/10 text-gray-600 border-gray-500/20',
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${colors[type]}`}>
      {labels[type]}
    </span>
  );
};

const StatusBadge = ({ status }: { status?: ScimProvider['sync_status'] }) => {
  if (!status) return null;

  const config = {
    idle: { icon: <CheckCircle size={14} />, class: 'bg-green-500/10 text-green-600', label: 'Idle' },
    syncing: { icon: <RefreshCw size={14} className="animate-spin" />, class: 'bg-blue-500/10 text-blue-600', label: 'Syncing' },
    error: { icon: <XCircle size={14} />, class: 'bg-red-500/10 text-red-600', label: 'Error' },
  };

  const { icon, class: className, label } = config[status];

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${className}`}>
      {icon}
      {label}
    </span>
  );
};

export function AdminScimPage() {
  const { showToast } = useToast();
  const [providers, setProviders] = useState<ScimProvider[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  // Modal states
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isTokenModalOpen, setIsTokenModalOpen] = useState(false);
  const [isLogsModalOpen, setIsLogsModalOpen] = useState(false);

  const [selectedProvider, setSelectedProvider] = useState<ScimProvider | null>(null);
  const [syncLogs, setSyncLogs] = useState<ScimSyncLog[]>([]);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);

  // Form states
  const [formData, setFormData] = useState<{
    name: string;
    type: ScimProvider['type'];
    enabled: boolean;
  }>({
    name: '',
    type: 'generic',
    enabled: true,
  });

  const loadProviders = async () => {
    setIsLoading(true);
    try {
      const response = await scimAdminService.listProviders();
      setProviders(response.providers || []);
    } catch (error) {
      console.error('Failed to load SCIM providers:', error);
      showToast({ title: 'Failed to load SCIM providers', type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadProviders();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredProviders = providers.filter(p =>
    p.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleCreate = async () => {
    try {
      await scimAdminService.createProvider(formData);
      showToast({ title: 'SCIM provider created successfully', type: 'success' });
      setIsCreateModalOpen(false);
      setFormData({ name: '', type: 'generic', enabled: true });
      loadProviders();
    } catch (error) {
      console.error('Failed to create provider:', error);
      showToast({ title: 'Failed to create SCIM provider', type: 'error' });
    }
  };

  const handleUpdate = async () => {
    if (!selectedProvider) return;
    try {
      await scimAdminService.updateProvider(selectedProvider.id, {
        name: formData.name,
        enabled: formData.enabled,
      });
      showToast({ title: 'SCIM provider updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedProvider(null);
      loadProviders();
    } catch (error) {
      console.error('Failed to update provider:', error);
      showToast({ title: 'Failed to update SCIM provider', type: 'error' });
    }
  };

  const handleDelete = async () => {
    if (!selectedProvider) return;
    try {
      await scimAdminService.deleteProvider(selectedProvider.id);
      showToast({ title: 'SCIM provider deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedProvider(null);
      loadProviders();
    } catch (error) {
      console.error('Failed to delete provider:', error);
      showToast({ title: 'Failed to delete SCIM provider', type: 'error' });
    }
  };

  const handleRegenerateToken = async (provider: ScimProvider) => {
    try {
      const response = await scimAdminService.regenerateToken(provider.id);
      setNewToken(response.token);
      setSelectedProvider(provider);
      setIsTokenModalOpen(true);
      showToast({ title: 'Token regenerated successfully', type: 'success' });
    } catch (error) {
      console.error('Failed to regenerate token:', error);
      showToast({ title: 'Failed to regenerate token', type: 'error' });
    }
  };

  const handleTriggerSync = async (provider: ScimProvider) => {
    try {
      await scimAdminService.triggerSync(provider.id);
      showToast({ title: 'Sync triggered successfully', type: 'success' });
      loadProviders();
    } catch (error) {
      console.error('Failed to trigger sync:', error);
      showToast({ title: 'Failed to trigger sync', type: 'error' });
    }
  };

  const openEditModal = (provider: ScimProvider) => {
    setSelectedProvider(provider);
    setFormData({
      name: provider.name,
      type: provider.type,
      enabled: provider.enabled,
    });
    setIsEditModalOpen(true);
  };

  const openLogsModal = async (provider: ScimProvider) => {
    setSelectedProvider(provider);
    try {
      const response = await scimAdminService.getSyncLogs(provider.id, { limit: 50 });
      setSyncLogs(response.logs || []);
      setIsLogsModalOpen(true);
    } catch (error) {
      console.error('Failed to load sync logs:', error);
      showToast({ title: 'Failed to load sync logs', type: 'error' });
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">SCIM Provisioning</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Configure identity providers for automated user provisioning
          </p>
        </div>
        <Button onClick={() => setIsCreateModalOpen(true)} leftIcon={<Plus size={16} />}>
          Add Provider
        </Button>
      </div>

      {/* Info Card */}
      <Card className="bg-blue-50/50 border-blue-200">
        <CardContent className="py-4">
          <p className="text-sm text-blue-800">
            <strong>SCIM 2.0 Endpoint:</strong>{' '}
            <code className="px-2 py-1 bg-blue-100 rounded text-xs">
              {window.location.origin}/v1/scim/v1
            </code>
          </p>
          <p className="text-sm text-blue-700 mt-2">
            Use the bearer token from your provider configuration to authenticate SCIM requests from your identity provider.
          </p>
        </CardContent>
      </Card>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--color-text-muted)]" />
          <Input
            type="text"
            placeholder="Search providers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Providers List */}
      {isLoading ? (
        <div className="text-center py-12 text-[var(--color-text-muted)]">Loading...</div>
      ) : filteredProviders.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Server className="w-12 h-12 mx-auto mb-4 text-[var(--color-text-muted)]" />
            <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
              {searchQuery ? 'No providers found' : 'No SCIM providers configured'}
            </h3>
            <p className="text-[var(--color-text-secondary)] mb-4">
              {searchQuery ? 'Try adjusting your search' : 'Add a provider to enable automated user provisioning'}
            </p>
            {!searchQuery && (
              <Button onClick={() => setIsCreateModalOpen(true)} leftIcon={<Plus size={16} />}>
                Add Provider
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredProviders.map((provider) => (
            <Card key={provider.id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-lg bg-[var(--color-primary-dark)] flex items-center justify-center">
                      <Server size={24} className="text-[#D4D4D4]" />
                    </div>
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="font-medium text-[var(--color-text-primary)]">{provider.name}</h3>
                        <ProviderTypeBadge type={provider.type} />
                        <StatusBadge status={provider.sync_status} />
                        {!provider.enabled && (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                            Disabled
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-sm text-[var(--color-text-muted)]">
                        {provider.last_sync_at && (
                          <span className="flex items-center gap-1">
                            <Clock size={14} />
                            Last sync: {new Date(provider.last_sync_at).toLocaleString()}
                          </span>
                        )}
                        {provider.sync_error && (
                          <span className="text-red-500">{provider.sync_error}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button size="sm" variant="ghost" onClick={() => handleTriggerSync(provider)} title="Trigger sync">
                      <RefreshCw size={16} />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleRegenerateToken(provider)} title="Regenerate token">
                      <Key size={16} />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => openLogsModal(provider)} title="View logs">
                      <Clock size={16} />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => openEditModal(provider)} title="Edit">
                      <Edit size={16} />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => { setSelectedProvider(provider); setIsDeleteModalOpen(true); }}
                      className="text-[var(--color-error)] hover:bg-[var(--color-error)]/10"
                      title="Delete"
                    >
                      <Trash2 size={16} />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create Provider Modal */}
      <Modal isOpen={isCreateModalOpen} onClose={() => setIsCreateModalOpen(false)} title="Add SCIM Provider">
        <div className="space-y-4">
          <Input
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g., Okta Production"
          />
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Provider Type
            </label>
            <select
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value as ScimProvider['type'] })}
              className="w-full px-4 py-2.5 rounded-xl border border-[var(--color-border)] bg-white text-[var(--color-text-primary)] focus:border-[var(--color-medium)] focus:outline-none"
            >
              <option value="okta">Okta</option>
              <option value="azure_ad">Azure AD</option>
              <option value="onelogin">OneLogin</option>
              <option value="generic">Generic SCIM 2.0</option>
            </select>
          </div>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded border-[var(--color-border)]"
            />
            <span className="text-sm text-[var(--color-text-primary)]">Enable provider</span>
          </label>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsCreateModalOpen(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={!formData.name}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Edit Provider Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Edit SCIM Provider">
        <div className="space-y-4">
          <Input
            label="Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="e.g., Okta Production"
          />
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded border-[var(--color-border)]"
            />
            <span className="text-sm text-[var(--color-text-primary)]">Enable provider</span>
          </label>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsEditModalOpen(false)}>Cancel</Button>
            <Button onClick={handleUpdate} disabled={!formData.name}>Save Changes</Button>
          </div>
        </div>
      </Modal>

      {/* Delete Provider Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)} title="Delete SCIM Provider">
        <div className="space-y-4">
          <p className="text-[var(--color-text-secondary)]">
            Are you sure you want to delete <strong>{selectedProvider?.name}</strong>? This will stop all user provisioning from this provider.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsDeleteModalOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={handleDelete}>Delete</Button>
          </div>
        </div>
      </Modal>

      {/* Token Modal */}
      <Modal isOpen={isTokenModalOpen} onClose={() => { setIsTokenModalOpen(false); setNewToken(null); setShowToken(false); }} title="SCIM Bearer Token">
        <div className="space-y-4">
          <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-sm text-yellow-800">
              <strong>Important:</strong> This token will only be shown once. Copy it now and configure it in your identity provider.
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Bearer Token for {selectedProvider?.name}
            </label>
            <div className="relative">
              <input
                type={showToken ? 'text' : 'password'}
                value={newToken || ''}
                readOnly
                className="w-full px-4 py-2.5 pr-20 rounded-xl border border-[var(--color-border)] bg-gray-50 text-[var(--color-text-primary)] font-mono text-sm"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <button
                  onClick={() => setShowToken(!showToken)}
                  className="p-2 hover:bg-gray-200 rounded"
                >
                  {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
                <button
                  onClick={() => {
                    if (newToken) {
                      navigator.clipboard.writeText(newToken);
                      showToast({ title: 'Token copied to clipboard', type: 'success' });
                    }
                  }}
                  className="px-3 py-1 text-sm bg-[var(--color-primary-dark)] text-white rounded hover:opacity-90"
                >
                  Copy
                </button>
              </div>
            </div>
          </div>
          <div className="flex justify-end">
            <Button onClick={() => { setIsTokenModalOpen(false); setNewToken(null); setShowToken(false); }}>Done</Button>
          </div>
        </div>
      </Modal>

      {/* Logs Modal */}
      <Modal isOpen={isLogsModalOpen} onClose={() => setIsLogsModalOpen(false)} title={`Sync Logs - ${selectedProvider?.name}`} size="lg">
        <div className="space-y-4">
          {syncLogs.length === 0 ? (
            <div className="text-center py-8 text-[var(--color-text-muted)]">
              No sync logs yet
            </div>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {syncLogs.map((log) => (
                <div
                  key={log.id}
                  className={`p-3 rounded-lg border ${
                    log.status === 'success'
                      ? 'bg-green-50 border-green-200'
                      : 'bg-red-50 border-red-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {log.status === 'success' ? (
                        <CheckCircle size={16} className="text-green-600" />
                      ) : (
                        <XCircle size={16} className="text-red-600" />
                      )}
                      <span className="font-medium text-sm">
                        {log.action} - {log.resource_type}
                      </span>
                    </div>
                    <span className="text-xs text-[var(--color-text-muted)]">
                      {new Date(log.created_at).toLocaleString()}
                    </span>
                  </div>
                  {log.error_message && (
                    <p className="text-sm text-red-600 mt-1">{log.error_message}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}

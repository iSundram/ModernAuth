import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  CheckCircle,
  XCircle,
  Clock,
  Globe,
  AlertCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Badge, Modal, Input, ConfirmDialog } from '../components/ui';
import { apiKeyService } from '../api/services';
import { useToast } from '../components/ui/Toast';
import type { APIKey, CreateAPIKeyRequest } from '../types';

export function ApiKeysPage() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);
  const [selectedKey, setSelectedKey] = useState<APIKey | null>(null);
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch API keys
  const { data: apiKeys = [], isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => apiKeyService.list(),
  });

  // Create API key mutation
  const createKeyMutation = useMutation({
    mutationFn: (data: CreateAPIKeyRequest) => apiKeyService.create(data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setNewKeyValue(response.key);
      showToast({ 
        title: 'Success', 
        message: 'API key created successfully. Copy it now - you won\'t be able to see it again!', 
        type: 'success' 
      });
      setIsCreateModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create API key', type: 'error' });
    },
  });

  // Revoke API key mutation
  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) => apiKeyService.revoke(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      showToast({ title: 'Success', message: 'API key revoked successfully', type: 'success' });
      setIsRevokeModalOpen(false);
      setSelectedKey(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to revoke API key', type: 'error' });
    },
  });

  // Delete API key mutation
  const deleteKeyMutation = useMutation({
    mutationFn: (id: string) => apiKeyService.revoke(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      showToast({ title: 'Success', message: 'API key deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedKey(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete API key', type: 'error' });
    },
  });

  const handleCopyKey = (key: string, keyId: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKeyId(keyId);
    showToast({ title: 'Copied', message: 'API key copied to clipboard', type: 'success' });
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  const activeKeys = apiKeys.filter(k => k.is_active && !k.revoked_at).length;
  const revokedKeys = apiKeys.filter(k => k.revoked_at).length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">API Keys</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Manage API keys for programmatic access to your account.
          </p>
        </div>
        <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
          Create API Key
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20">
              <Key size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{apiKeys.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Keys</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{activeKeys}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Active</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-red-500/10">
              <XCircle size={24} className="text-red-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{revokedKeys}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Revoked</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* API Keys List */}
      <Card>
        <CardHeader>
          <CardTitle>Your API Keys</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-12">
              <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-[var(--color-text-secondary)]">Loading API keys...</p>
            </div>
          ) : apiKeys.length === 0 ? (
            <div className="text-center py-12">
              <Key size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
              <p className="text-[var(--color-text-secondary)] mb-2">No API keys found</p>
              <p className="text-sm text-[var(--color-text-muted)] mb-4">
                Create your first API key to get started
              </p>
              <Button onClick={() => setIsCreateModalOpen(true)}>
                Create API Key
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {apiKeys.map((key) => (
                <div
                  key={key.id}
                  className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-medium text-[var(--color-text-primary)]">{key.name}</h3>
                        {key.is_active && !key.revoked_at ? (
                          <Badge variant="success" size="sm">
                            <CheckCircle size={12} className="mr-1" />
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="error" size="sm">
                            <XCircle size={12} className="mr-1" />
                            Revoked
                          </Badge>
                        )}
                      </div>
                      {key.description && (
                        <p className="text-sm text-[var(--color-text-secondary)] mb-3">{key.description}</p>
                      )}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <p className="text-xs text-[var(--color-text-muted)] mb-1">Key Prefix</p>
                          <p className="font-mono text-xs text-[var(--color-text-primary)]">{key.key_prefix}</p>
                        </div>
                        {key.scopes && key.scopes.length > 0 && (
                          <div>
                            <p className="text-xs text-[var(--color-text-muted)] mb-1">Scopes</p>
                            <div className="flex flex-wrap gap-1">
                              {key.scopes.slice(0, 2).map((scope) => (
                                <Badge key={scope} variant="default" size="sm">{scope}</Badge>
                              ))}
                              {key.scopes.length > 2 && (
                                <Badge variant="default" size="sm">+{key.scopes.length - 2}</Badge>
                              )}
                            </div>
                          </div>
                        )}
                        {key.last_used_at && (
                          <div>
                            <p className="text-xs text-[var(--color-text-muted)] mb-1">Last Used</p>
                            <div className="flex items-center gap-1">
                              <Clock size={12} className="text-[var(--color-text-muted)]" />
                              <p className="text-xs text-[var(--color-text-secondary)]">
                                {new Date(key.last_used_at).toLocaleDateString()}
                              </p>
                            </div>
                          </div>
                        )}
                        {key.last_used_ip && (
                          <div>
                            <p className="text-xs text-[var(--color-text-muted)] mb-1">Last IP</p>
                            <div className="flex items-center gap-1">
                              <Globe size={12} className="text-[var(--color-text-muted)]" />
                              <p className="font-mono text-xs text-[var(--color-text-secondary)]">
                                {key.last_used_ip}
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                      <div className="mt-3 text-xs text-[var(--color-text-muted)]">
                        Created: {new Date(key.created_at).toLocaleString()}
                        {key.expires_at && (
                          <span className="ml-4">
                            Expires: {new Date(key.expires_at).toLocaleString()}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      {key.is_active && !key.revoked_at && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedKey(key);
                              setIsRevokeModalOpen(true);
                            }}
                            className="text-red-500 hover:text-red-600"
                            title="Revoke"
                          >
                            Revoke
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedKey(key);
                              setIsDeleteModalOpen(true);
                            }}
                            className="text-red-500 hover:text-red-600"
                            title="Delete"
                          >
                            <Trash2 size={16} />
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create API Key Modal */}
      <CreateApiKeyModal
        isOpen={isCreateModalOpen}
        onClose={() => {
          setIsCreateModalOpen(false);
          setNewKeyValue(null);
        }}
        onSubmit={(data) => createKeyMutation.mutate(data)}
        isLoading={createKeyMutation.isPending}
      />

      {/* New Key Display Modal */}
      <Modal
        isOpen={!!newKeyValue}
        onClose={() => setNewKeyValue(null)}
        title="API Key Created"
        size="md"
      >
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
            <div className="flex gap-3">
              <AlertCircle className="text-yellow-500 shrink-0" size={20} />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Important: Copy your API key now
                </p>
                <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                  You won't be able to see this key again after closing this dialog.
                </p>
              </div>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
              Your API Key
            </label>
            <div className="flex items-center gap-2">
              <Input
                value={newKeyValue || ''}
                readOnly
                className="font-mono text-sm"
              />
              <Button
                variant="outline"
                onClick={() => newKeyValue && handleCopyKey(newKeyValue, 'new')}
                title="Copy"
              >
                {copiedKeyId === 'new' ? <CheckCircle size={16} className="text-green-500" /> : <Copy size={16} />}
              </Button>
            </div>
          </div>
          <div className="flex justify-end pt-4">
            <Button variant="primary" onClick={() => setNewKeyValue(null)}>
              I've Copied It
            </Button>
          </div>
        </div>
      </Modal>

      {/* Revoke Confirmation */}
      <ConfirmDialog
        isOpen={isRevokeModalOpen}
        onClose={() => {
          setIsRevokeModalOpen(false);
          setSelectedKey(null);
        }}
        onConfirm={() => selectedKey && revokeKeyMutation.mutate(selectedKey.id)}
        title="Revoke API Key"
        message={`Are you sure you want to revoke "${selectedKey?.name}"? This will immediately invalidate the key.`}
        confirmText="Revoke"
        variant="danger"
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedKey(null);
        }}
        onConfirm={() => selectedKey && deleteKeyMutation.mutate(selectedKey.id)}
        title="Delete API Key"
        message={`Are you sure you want to delete "${selectedKey?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  );
}

// Create API Key Modal Component
function CreateApiKeyModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateAPIKeyRequest) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<CreateAPIKeyRequest>({
    name: '',
    description: '',
    scopes: [],
    rate_limit: undefined,
    allowed_ips: [],
    expires_at: undefined,
  });
  const [scopeInput, setScopeInput] = useState('');
  const [ipInput, setIpInput] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name) {
      return;
    }
    onSubmit(formData);
    setFormData({
      name: '',
      description: '',
      scopes: [],
      rate_limit: undefined,
      allowed_ips: [],
      expires_at: undefined,
    });
    setScopeInput('');
    setIpInput('');
  };

  const addScope = () => {
    if (scopeInput.trim()) {
      setFormData({
        ...formData,
        scopes: [...(formData.scopes || []), scopeInput.trim()],
      });
      setScopeInput('');
    }
  };

  const removeScope = (scope: string) => {
    setFormData({
      ...formData,
      scopes: formData.scopes?.filter(s => s !== scope) || [],
    });
  };

  const addIP = () => {
    if (ipInput.trim()) {
      setFormData({
        ...formData,
        allowed_ips: [...(formData.allowed_ips || []), ipInput.trim()],
      });
      setIpInput('');
    }
  };

  const removeIP = (ip: string) => {
    setFormData({
      ...formData,
      allowed_ips: formData.allowed_ips?.filter(i => i !== ip) || [],
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create API Key" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
          placeholder="My API Key"
        />
        <Input
          label="Description (Optional)"
          value={formData.description || ''}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="What is this key used for?"
        />
        
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Scopes (Optional)
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={scopeInput}
              onChange={(e) => setScopeInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addScope();
                }
              }}
              placeholder="Enter scope (e.g., read:users)"
            />
            <Button type="button" variant="outline" onClick={addScope}>
              Add
            </Button>
          </div>
          {formData.scopes && formData.scopes.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {formData.scopes.map((scope) => (
                <Badge key={scope} variant="default" size="sm">
                  {scope}
                  <button
                    type="button"
                    onClick={() => removeScope(scope)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <Input
          label="Rate Limit (Optional)"
          type="number"
          value={formData.rate_limit?.toString() || ''}
          onChange={(e) => setFormData({ ...formData, rate_limit: e.target.value ? parseInt(e.target.value) : undefined })}
          placeholder="Requests per minute"
        />

        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Allowed IPs (Optional)
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addIP();
                }
              }}
              placeholder="Enter IP address"
            />
            <Button type="button" variant="outline" onClick={addIP}>
              Add
            </Button>
          </div>
          {formData.allowed_ips && formData.allowed_ips.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {formData.allowed_ips.map((ip) => (
                <Badge key={ip} variant="default" size="sm">
                  {ip}
                  <button
                    type="button"
                    onClick={() => removeIP(ip)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <Input
          label="Expires At (Optional)"
          type="datetime-local"
          value={formData.expires_at ? new Date(formData.expires_at).toISOString().slice(0, 16) : ''}
          onChange={(e) => setFormData({ ...formData, expires_at: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
        />

        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Create API Key
          </Button>
        </div>
      </form>
    </Modal>
  );
}

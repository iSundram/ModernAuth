import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Building2,
  Plus,
  Trash2,
  Edit,
  Globe,
  CheckCircle,
  XCircle,
  Settings,
  Users,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Badge, Modal, Input, ConfirmDialog } from '../../components/ui';
import { tenantService, userService } from '../../api/services';
import { useToast } from '../../components/ui/Toast';
import type { Tenant, CreateTenantRequest, UpdateTenantRequest, TenantSecurityStats, User } from '../../types';

function TenantStats({ tenantId }: { tenantId: string }) {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['tenant-stats', tenantId],
    queryFn: () => tenantService.getStats(tenantId),
  });

  const { data: security, isLoading: securityLoading } = useQuery<TenantSecurityStats>({
    queryKey: ['tenant-security-stats', tenantId],
    queryFn: () => tenantService.getSecurityStats(tenantId),
  });

  if (statsLoading || securityLoading) {
    return <div className="animate-pulse h-4 w-40 bg-[var(--color-gray-light)] rounded" />;
  }
  if (!stats || !security) return null;

  const maxUsers = stats.max_users || 0;
  const userCount = stats.user_count || 0;
  const usagePercent = maxUsers > 0 ? Math.min(100, Math.round((userCount / maxUsers) * 100)) : undefined;

  return (
    <div className="mt-2 space-y-2">
      <div className="flex justify-between items-center text-xs text-[var(--color-text-muted)]">
        <span>
          Users:{' '}
          <span className="text-[var(--color-text-primary)] font-medium">
            {userCount}
            {maxUsers > 0 ? ` / ${maxUsers}` : ''}
          </span>
        </span>
        {stats.plan && (
          <span>
            Plan:{' '}
            <span className="text-[var(--color-text-primary)] font-medium">
              {stats.plan}
            </span>
          </span>
        )}
      </div>
      {usagePercent !== undefined && (
        <div className="w-full h-1.5 rounded-full bg-[var(--color-border-light)] overflow-hidden">
          <div
            className={`h-full rounded-full ${
              usagePercent > 90 ? 'bg-red-500' : usagePercent > 70 ? 'bg-yellow-500' : 'bg-green-500'
            }`}
            style={{ width: `${usagePercent}%` }}
          />
        </div>
      )}
      <div className="flex gap-4 text-[10px] text-[var(--color-text-muted)]">
        <span>
          Active:{' '}
          <span className="text-[var(--color-text-primary)] font-medium">
            {security.active_users}/{security.total_users}
          </span>
        </span>
        <span>
          Verified:{' '}
          <span className="text-[var(--color-text-primary)] font-medium">
            {security.verified_users}
          </span>
        </span>
        <span>
          MFA:{' '}
          <span className="text-[var(--color-text-primary)] font-medium">
            {security.mfa_enabled_users}
          </span>
        </span>
      </div>
    </div>
  );
}

export function AdminTenantsPage() {
  const navigate = useNavigate();
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [expandedStats, setExpandedStats] = useState<Record<string, boolean>>({});
  const [expandedUsers, setExpandedUsers] = useState<Record<string, boolean>>({});
  
  // Fetch all users for tenant membership display
  const { data: allUsers = [] } = useQuery({
    queryKey: ['all-users'],
    queryFn: () => userService.list(),
  });
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const toggleStats = (id: string) => {
    setExpandedStats(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Fetch tenants
  const { data: tenants = [], isLoading } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantService.list(),
  });

  // Create tenant mutation
  const createTenantMutation = useMutation({
    mutationFn: (data: CreateTenantRequest) => tenantService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      showToast({ title: 'Success', message: 'Tenant created successfully', type: 'success' });
      setIsCreateModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create tenant', type: 'error' });
    },
  });

  // Update tenant mutation
  const updateTenantMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateTenantRequest }) => 
      tenantService.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      showToast({ title: 'Success', message: 'Tenant updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedTenant(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update tenant', type: 'error' });
    },
  });

  // Delete tenant mutation
  const deleteTenantMutation = useMutation({
    mutationFn: (id: string) => tenantService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      showToast({ title: 'Success', message: 'Tenant deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedTenant(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete tenant', type: 'error' });
    },
  });

  const activeTenants = tenants.filter(t => t.is_active).length;
  const totalTenants = tenants.length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Tenant Management</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Manage multi-tenant organizations and their settings.
          </p>
        </div>
        <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
          Create Tenant
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20">
              <Building2 size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{totalTenants}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Tenants</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{activeTenants}</p>
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
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{totalTenants - activeTenants}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Inactive</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tenants List */}
      <Card>
        <CardHeader>
          <CardTitle>Tenants</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-12">
              <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-[var(--color-text-secondary)]">Loading tenants...</p>
            </div>
          ) : tenants.length === 0 ? (
            <div className="text-center py-12">
              <Building2 size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
              <p className="text-[var(--color-text-secondary)] mb-2">No tenants found</p>
              <p className="text-sm text-[var(--color-text-muted)] mb-4">
                Create your first tenant to get started
              </p>
              <Button onClick={() => setIsCreateModalOpen(true)}>
                Create Tenant
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {tenants.map((tenant) => (
                <div
                  key={tenant.id}
                  className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-medium text-[var(--color-text-primary)]">{tenant.name}</h3>
                        {tenant.is_active ? (
                          <Badge variant="success" size="sm">
                            <CheckCircle size={12} className="mr-1" />
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="error" size="sm">
                            <XCircle size={12} className="mr-1" />
                            Inactive
                          </Badge>
                        )}
                        <Badge variant="default" size="sm">{tenant.plan}</Badge>
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center gap-4 text-sm">
                          <div className="flex items-center gap-2">
                            <Settings size={14} className="text-[var(--color-text-muted)]" />
                            <span className="text-[var(--color-text-secondary)]">Slug: </span>
                            <span className="font-mono text-xs text-[var(--color-text-primary)]">{tenant.slug}</span>
                          </div>
                          {tenant.domain && (
                            <div className="flex items-center gap-2">
                              <Globe size={14} className="text-[var(--color-text-muted)]" />
                              <span className="text-[var(--color-text-secondary)]">Domain: </span>
                              <span className="text-[var(--color-text-primary)]">{tenant.domain}</span>
                            </div>
                          )}
                        </div>
                        {tenant.logo_url && (
                          <div className="flex items-center gap-2">
                            <img src={tenant.logo_url} alt={tenant.name} className="w-8 h-8 rounded" />
                            <span className="text-xs text-[var(--color-text-muted)]">Logo URL configured</span>
                          </div>
                        )}
                        <div className="text-xs text-[var(--color-text-muted)]">
                          Created: {new Date(tenant.created_at).toLocaleString()}
                        </div>
                        <div className="mt-3">
                          <button 
                            onClick={() => toggleStats(tenant.id)}
                            className="text-xs font-medium text-[var(--color-info)] hover:underline flex items-center gap-1"
                          >
                            {expandedStats[tenant.id] ? 'Hide Stats' : 'Show Stats'}
                          </button>
                          {expandedStats[tenant.id] && <TenantStats tenantId={tenant.id} />}
                        </div>
                        <div className="mt-3 pt-3 border-t border-[var(--color-border-light)]">
                          <button
                            onClick={() => setExpandedUsers({ ...expandedUsers, [tenant.id]: !expandedUsers[tenant.id] })}
                            className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                          >
                            {expandedUsers[tenant.id] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            <Users size={16} />
                            <span>Members ({allUsers.filter(u => u.tenant_id === tenant.id).length})</span>
                          </button>
                          {expandedUsers[tenant.id] && (
                            <TenantMembers tenantId={tenant.id} users={allUsers} />
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedTenant(tenant);
                          setIsEditModalOpen(true);
                        }}
                        title="Edit"
                      >
                        <Edit size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/admin/tenants/${tenant.id}`)}
                        title="View Details"
                      >
                        <ExternalLink size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedTenant(tenant);
                          setIsDeleteModalOpen(true);
                        }}
                        className="text-red-500 hover:text-red-600"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Tenant Modal */}
      <CreateTenantModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={(data) => createTenantMutation.mutate(data)}
        isLoading={createTenantMutation.isPending}
      />

      {/* Edit Tenant Modal */}
      {selectedTenant && (
        <EditTenantModal
          isOpen={isEditModalOpen}
          onClose={() => {
            setIsEditModalOpen(false);
            setSelectedTenant(null);
          }}
          tenant={selectedTenant}
          onSubmit={(data) => updateTenantMutation.mutate({ id: selectedTenant.id, data })}
          isLoading={updateTenantMutation.isPending}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedTenant(null);
        }}
        onConfirm={() => selectedTenant && deleteTenantMutation.mutate(selectedTenant.id)}
        title="Delete Tenant"
        message={`Are you sure you want to delete "${selectedTenant?.name}"? This action cannot be undone and will affect all users in this tenant.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  );
}

// Create Tenant Modal Component
function CreateTenantModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateTenantRequest) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<CreateTenantRequest>({
    name: '',
    slug: '',
    domain: '',
    logo_url: '',
    plan: 'free',
    settings: {},
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.slug) {
      return;
    }
    onSubmit(formData);
    setFormData({
      name: '',
      slug: '',
      domain: '',
      logo_url: '',
      plan: 'free',
      settings: {},
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Tenant" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name *"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
          placeholder="Acme Corporation"
        />
        <Input
          label="Slug *"
          value={formData.slug}
          onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-') })}
          required
          placeholder="acme-corp"
        />
        <Input
          label="Domain (Optional)"
          value={formData.domain || ''}
          onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
          placeholder="acme.com"
        />
        <Input
          label="Logo URL (Optional)"
          value={formData.logo_url || ''}
          onChange={(e) => setFormData({ ...formData, logo_url: e.target.value })}
          placeholder="https://example.com/logo.png"
        />
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Plan
          </label>
          <select
            value={formData.plan}
            onChange={(e) => setFormData({ ...formData, plan: e.target.value })}
            className="w-full px-4 py-2 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
          >
            <option value="free">Free</option>
            <option value="starter">Starter</option>
            <option value="professional">Professional</option>
            <option value="enterprise">Enterprise</option>
          </select>
        </div>
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Create Tenant
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Tenant Members Component
function TenantMembers({ tenantId, users }: { tenantId: string; users: User[] }) {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const tenantUsers = users.filter(u => u.tenant_id === tenantId);
  const availableUsers = users.filter(u => !u.tenant_id || u.tenant_id !== tenantId);
  const [isAssignModalOpen, setIsAssignModalOpen] = useState(false);

  const assignUserMutation = useMutation({
    mutationFn: (userId: string) => tenantService.assignUser(tenantId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['all-users'] });
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      showToast({ title: 'Success', message: 'User assigned to tenant', type: 'success' });
      setIsAssignModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to assign user', type: 'error' });
    },
  });

  const removeUserMutation = useMutation({
    mutationFn: (userId: string) => tenantService.removeUser(tenantId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['all-users'] });
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
      showToast({ title: 'Success', message: 'User removed from tenant', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to remove user', type: 'error' });
    },
  });

  return (
    <div className="mt-3 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-[var(--color-text-secondary)]">
          {tenantUsers.length} member{tenantUsers.length !== 1 ? 's' : ''}
        </span>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setIsAssignModalOpen(true)}
          className="text-xs"
        >
          <Plus size={14} className="mr-1" />
          Add User
        </Button>
      </div>

      {tenantUsers.length === 0 ? (
        <div className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
          <p className="text-sm text-[var(--color-text-secondary)] text-center">
            No users assigned to this tenant
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {tenantUsers.map((user) => (
            <div key={user.id} className="p-2 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] flex items-center justify-between">
              <div className="flex-1">
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  {user.first_name && user.last_name 
                    ? `${user.first_name} ${user.last_name}` 
                    : user.username || user.email}
                </p>
                <p className="text-xs text-[var(--color-text-muted)]">{user.email}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={user.is_active ? 'success' : 'error'} size="sm">
                  {user.is_active ? 'Active' : 'Inactive'}
                </Badge>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (confirm(`Remove ${user.email} from this tenant?`)) {
                      removeUserMutation.mutate(user.id);
                    }
                  }}
                  className="text-red-500 hover:text-red-600"
                  title="Remove"
                >
                  <Trash2 size={14} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Assign User Modal */}
      <Modal
        isOpen={isAssignModalOpen}
        onClose={() => setIsAssignModalOpen(false)}
        title="Assign User to Tenant"
        size="md"
      >
        <div className="space-y-3">
          {availableUsers.length === 0 ? (
            <p className="text-sm text-[var(--color-text-secondary)] text-center py-4">
              No available users to assign
            </p>
          ) : (
            <div className="max-h-64 overflow-y-auto space-y-2">
              {availableUsers.map((user) => (
                <div
                  key={user.id}
                  className="p-3 rounded-lg border border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] cursor-pointer"
                  onClick={() => assignUserMutation.mutate(user.id)}
                >
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    {user.first_name && user.last_name 
                      ? `${user.first_name} ${user.last_name}` 
                      : user.username || user.email}
                  </p>
                  <p className="text-xs text-[var(--color-text-muted)]">{user.email}</p>
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-3 pt-4">
            <Button
              type="button"
              variant="ghost"
              onClick={() => setIsAssignModalOpen(false)}
              className="flex-1"
            >
              Cancel
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// Edit Tenant Modal Component
function EditTenantModal({
  isOpen,
  onClose,
  tenant,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  tenant: Tenant;
  onSubmit: (data: UpdateTenantRequest) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<UpdateTenantRequest>({
    name: tenant.name,
    domain: tenant.domain,
    logo_url: tenant.logo_url,
    plan: tenant.plan,
    is_active: tenant.is_active,
    settings: tenant.settings,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit Tenant" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name"
          value={formData.name || ''}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
        />
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Slug (read-only)
          </label>
          <Input value={tenant.slug} disabled />
        </div>
        <Input
          label="Domain"
          value={formData.domain || ''}
          onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
          placeholder="acme.com"
        />
        <Input
          label="Logo URL"
          value={formData.logo_url || ''}
          onChange={(e) => setFormData({ ...formData, logo_url: e.target.value })}
          placeholder="https://example.com/logo.png"
        />
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Plan
          </label>
          <select
            value={formData.plan}
            onChange={(e) => setFormData({ ...formData, plan: e.target.value })}
            className="w-full px-4 py-2 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
          >
            <option value="free">Free</option>
            <option value="starter">Starter</option>
            <option value="professional">Professional</option>
            <option value="enterprise">Enterprise</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="is_active"
            checked={formData.is_active ?? true}
            onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
            className="w-4 h-4 rounded border-[var(--color-border)]"
          />
          <label htmlFor="is_active" className="text-sm text-[var(--color-text-secondary)]">
            Active
          </label>
        </div>
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Save Changes
          </Button>
        </div>
      </form>
    </Modal>
  );
}

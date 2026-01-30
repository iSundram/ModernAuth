import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Plus,
  Trash2,
  Edit,
  Lock,
  CheckCircle,
  Key,
  Users,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button, Modal, Input, ConfirmDialog, LoadingBar } from '../../components/ui';
import { adminService, userService } from '../../api/services';
import { useToast } from '../../components/ui/Toast';
import type { Role, Permission } from '../../types';

export function AdminRolesPage() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isPermissionsModalOpen, setIsPermissionsModalOpen] = useState(false);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: () => adminService.listRoles(),
  });

  // Fetch all permissions for the permission modal
  const { data: permissions = [] } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => adminService.listPermissions(),
  });

  // Fetch all users to count users per role
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: () => userService.list(),
  });

  const { data: rolePermissions = [] } = useQuery({
    queryKey: ['role-permissions', selectedRole?.id],
    queryFn: () => selectedRole ? adminService.getRolePermissions(selectedRole.id) : Promise.resolve([]),
    enabled: isPermissionsModalOpen && selectedRole !== null,
  });

  // Note: This counts by role name matching user.role which may be 'admin' or 'user'
  // For custom RBAC roles, a dedicated endpoint would be needed
  const getUserCountForRole = (roleName: string) => {
    return users.filter(u => u.role === roleName).length;
  };

  const createRoleMutation = useMutation({
    mutationFn: (data: { name: string; description?: string; tenant_id?: string }) =>
      adminService.createRole(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      showToast({ title: 'Success', message: 'Role created successfully', type: 'success' });
      setIsCreateModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create role', type: 'error' });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { description?: string } }) =>
      adminService.updateRole(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      showToast({ title: 'Success', message: 'Role updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedRole(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update role', type: 'error' });
    },
  });

  const deleteRoleMutation = useMutation({
    mutationFn: (id: string) => adminService.deleteRole(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      showToast({ title: 'Success', message: 'Role deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedRole(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete role', type: 'error' });
    },
  });

  const assignPermissionMutation = useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      adminService.assignPermissionToRole(roleId, permissionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['role-permissions', selectedRole?.id] });
      showToast({ title: 'Success', message: 'Permission assigned', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to assign permission', type: 'error' });
    },
  });

  const removePermissionMutation = useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      adminService.removePermissionFromRole(roleId, permissionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['role-permissions', selectedRole?.id] });
      showToast({ title: 'Success', message: 'Permission removed', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to remove permission', type: 'error' });
    },
  });

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading} message="Loading roles..." />
      
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Role Management</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Create and manage system roles and permissions.
          </p>
        </div>
        <Button
          variant="primary"
          onClick={() => setIsCreateModalOpen(true)}
        >
          <Plus size={16} className="mr-2" />
          Create Role
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-blue-500/10">
              <Shield size={24} className="text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{roles.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Roles</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-purple-500/10">
              <Key size={24} className="text-purple-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{permissions.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Permissions</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <Users size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{users.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Users</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {roles.map((role) => (
          <Card key={role.id}>
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${role.name === 'admin' ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
                  <Shield size={20} className={role.name === 'admin' ? 'text-red-500' : 'text-blue-500'} />
                </div>
                <div>
                  <CardTitle className="capitalize">{role.name}</CardTitle>
                  {role.is_system && (
                    <Badge variant="default" size="sm" className="mt-1">System Role</Badge>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSelectedRole(role);
                    setIsPermissionsModalOpen(true);
                  }}
                  title="Manage Permissions"
                >
                  <Key size={16} />
                </Button>
                {!role.is_system && (
                  <>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setSelectedRole(role);
                        setIsEditModalOpen(true);
                      }}
                      title="Edit"
                    >
                      <Edit size={16} />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setSelectedRole(role);
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
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-secondary)] mb-1">Description</p>
                  <p className="text-sm text-[var(--color-text-primary)]">
                    {role.description || 'No description provided.'}
                  </p>
                </div>
                
                <div className="flex flex-wrap items-center gap-6 pt-4 border-t border-[var(--color-border-light)]">
                  <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
                    <Users size={16} />
                    <span className="font-medium">{getUserCountForRole(role.name)}</span> users
                  </div>
                  <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
                    <Lock size={16} />
                    Role ID: <span className="font-mono text-xs">{role.id}</span>
                  </div>
                  {role.created_at && (
                    <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
                      Created: {new Date(role.created_at).toLocaleDateString()}
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Available Permissions Reference */}
      {permissions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Available Permissions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {permissions.map((permission: Permission) => (
                <div
                  key={permission.id}
                  className="p-2 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] text-sm"
                >
                  <span className="font-mono text-[var(--color-text-primary)]">{permission.name}</span>
                  {permission.description && (
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">{permission.description}</p>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Create Role Modal */}
      <CreateRoleModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={(data) => createRoleMutation.mutate(data)}
        isLoading={createRoleMutation.isPending}
      />

      {/* Edit Role Modal */}
      {selectedRole && (
        <EditRoleModal
          isOpen={isEditModalOpen}
          onClose={() => {
            setIsEditModalOpen(false);
            setSelectedRole(null);
          }}
          role={selectedRole}
          onSubmit={(data) => updateRoleMutation.mutate({ id: selectedRole.id, data })}
          isLoading={updateRoleMutation.isPending}
        />
      )}

      {/* Delete Role Confirmation */}
      {selectedRole && (
        <ConfirmDialog
          isOpen={isDeleteModalOpen}
          onClose={() => {
            setIsDeleteModalOpen(false);
            setSelectedRole(null);
          }}
          onConfirm={() => deleteRoleMutation.mutate(selectedRole.id)}
          title="Delete Role"
          message={`Are you sure you want to delete the role "${selectedRole.name}"? This action cannot be undone.`}
          confirmText="Delete"
          variant="danger"
          loading={deleteRoleMutation.isPending}
        />
      )}

      {/* Permissions Modal */}
      {selectedRole && (
        <PermissionsModal
          isOpen={isPermissionsModalOpen}
          onClose={() => {
            setIsPermissionsModalOpen(false);
            setSelectedRole(null);
          }}
          role={selectedRole}
          permissions={permissions}
          rolePermissions={rolePermissions}
          onAssign={(permissionId) => assignPermissionMutation.mutate({ roleId: selectedRole.id, permissionId })}
          onRemove={(permissionId) => removePermissionMutation.mutate({ roleId: selectedRole.id, permissionId })}
        />
      )}
    </div>
  );
}

// Create Role Modal
function CreateRoleModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: { name: string; description?: string; tenant_id?: string }) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({ name: '', description: '', tenant_id: '' });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name: formData.name,
      description: formData.description || undefined,
      tenant_id: formData.tenant_id || undefined,
    });
    setFormData({ name: '', description: '', tenant_id: '' });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Role" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Role Name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="e.g., manager, editor"
          required
        />
        <Input
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="Role description"
        />
        <Input
          label="Tenant ID (optional)"
          value={formData.tenant_id}
          onChange={(e) => setFormData({ ...formData, tenant_id: e.target.value })}
          placeholder="Leave empty for global role"
        />
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Create Role
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Edit Role Modal
function EditRoleModal({
  isOpen,
  onClose,
  role,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  role: Role;
  onSubmit: (data: { description?: string }) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({ description: role.description || '' });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ description: formData.description || undefined });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit Role" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Role Name (read-only)
          </label>
          <Input value={role.name} disabled />
        </div>
        <Input
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="Role description"
        />
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

// Permissions Modal
function PermissionsModal({
  isOpen,
  onClose,
  role,
  permissions,
  rolePermissions,
  onAssign,
  onRemove,
}: {
  isOpen: boolean;
  onClose: () => void;
  role: Role;
  permissions: any[];
  rolePermissions: any[];
  onAssign: (permissionId: string) => void;
  onRemove: (permissionId: string) => void;
}) {
  const assignedPermissionIds = new Set(rolePermissions.map((p: any) => p.id));

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Manage Permissions: ${role.name}`} size="lg">
      <div className="space-y-4">
        <p className="text-sm text-[var(--color-text-secondary)]">
          Assign or remove permissions for this role.
        </p>
        
        <div className="max-h-96 overflow-y-auto space-y-2">
          {permissions.map((permission) => {
            const isAssigned = assignedPermissionIds.has(permission.id);
            return (
              <div
                key={permission.id}
                className="p-3 rounded-lg border border-[var(--color-border)] flex items-center justify-between"
              >
                <div className="flex-1">
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    {permission.name}
                  </p>
                  {permission.description && (
                    <p className="text-xs text-[var(--color-text-muted)] mt-1">
                      {permission.description}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {isAssigned ? (
                    <>
                      <Badge variant="success" size="sm">
                        <CheckCircle size={12} className="mr-1" />
                        Assigned
                      </Badge>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onRemove(permission.id)}
                        className="text-red-500 hover:text-red-600"
                      >
                        Remove
                      </Button>
                    </>
                  ) : (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => onAssign(permission.id)}
                    >
                      Assign
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex gap-3 pt-4">
          <Button variant="ghost" onClick={onClose} className="flex-1">
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
}

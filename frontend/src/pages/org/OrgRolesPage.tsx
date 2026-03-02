import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Plus,
  Trash2,
  Edit,
  Key,
  Users,
  Check,
  X,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button, Modal, Input, ConfirmDialog, LoadingBar } from '../../components/ui';
import { tenantService, adminService } from '../../api/services';
import { useTenant } from '../../hooks/useTenant';
import { useToast } from '../../components/ui/Toast';
import type { Role, Permission } from '../../types';

export function OrgRolesPage() {
  const { tenant } = useTenant();
  const tenantId = tenant?.id;
  
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isPermissionsModalOpen, setIsPermissionsModalOpen] = useState(false);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDescription, setNewRoleDescription] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['tenant-roles', tenantId],
    queryFn: () => tenantId ? tenantService.listRoles(tenantId) : Promise.resolve([]),
    enabled: !!tenantId,
  });

  // Fetch all available permissions for assignment
  const { data: allPermissions = [] } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => adminService.listPermissions(),
  });

  // Fetch permissions for selected role
  const { data: rolePermissions = [] } = useQuery({
    queryKey: ['tenant-role-permissions', tenantId, selectedRole?.id],
    queryFn: () => (tenantId && selectedRole) ? tenantService.getRolePermissions(tenantId, selectedRole.id) : Promise.resolve([]),
    enabled: isPermissionsModalOpen && !!tenantId && !!selectedRole,
  });

  const createRoleMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) =>
      tenantId ? tenantService.createRole(tenantId, data) : Promise.reject(new Error('No tenant')),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-roles', tenantId] });
      showToast({ title: 'Role created successfully', type: 'success' });
      setIsCreateModalOpen(false);
      setNewRoleName('');
      setNewRoleDescription('');
    },
    onError: (error: Error) => {
      showToast({ title: error.message || 'Failed to create role', type: 'error' });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: ({ roleId, data }: { roleId: string; data: { description?: string } }) =>
      tenantId ? tenantService.updateRole(tenantId, roleId, data) : Promise.reject(new Error('No tenant')),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-roles', tenantId] });
      showToast({ title: 'Role updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedRole(null);
    },
    onError: (error: Error) => {
      showToast({ title: error.message || 'Failed to update role', type: 'error' });
    },
  });

  const deleteRoleMutation = useMutation({
    mutationFn: (roleId: string) =>
      tenantId ? tenantService.deleteRole(tenantId, roleId) : Promise.reject(new Error('No tenant')),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-roles', tenantId] });
      showToast({ title: 'Role deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedRole(null);
    },
    onError: (error: Error) => {
      showToast({ title: error.message || 'Failed to delete role', type: 'error' });
    },
  });

  const assignPermissionMutation = useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      tenantId ? tenantService.assignPermissionToRole(tenantId, roleId, permissionId) : Promise.reject(new Error('No tenant')),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-role-permissions', tenantId, selectedRole?.id] });
      showToast({ title: 'Permission assigned', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: error.message || 'Failed to assign permission', type: 'error' });
    },
  });

  const removePermissionMutation = useMutation({
    mutationFn: ({ roleId, permissionId }: { roleId: string; permissionId: string }) =>
      tenantId ? tenantService.removePermissionFromRole(tenantId, roleId, permissionId) : Promise.reject(new Error('No tenant')),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenant-role-permissions', tenantId, selectedRole?.id] });
      showToast({ title: 'Permission removed', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: error.message || 'Failed to remove permission', type: 'error' });
    },
  });

  const handleCreateRole = () => {
    if (!newRoleName.trim()) {
      showToast({ title: 'Role name is required', type: 'error' });
      return;
    }
    createRoleMutation.mutate({
      name: newRoleName.trim(),
      description: newRoleDescription.trim() || undefined,
    });
  };

  const handleEditRole = () => {
    if (!selectedRole) return;
    updateRoleMutation.mutate({
      roleId: selectedRole.id,
      data: { description: editDescription.trim() || undefined },
    });
  };

  const handleDeleteRole = () => {
    if (!selectedRole) return;
    deleteRoleMutation.mutate(selectedRole.id);
  };

  const isPermissionAssigned = (permissionId: string) => {
    return rolePermissions.some((p: Permission) => p.id === permissionId);
  };

  const handleTogglePermission = (permission: Permission) => {
    if (!selectedRole) return;
    
    if (isPermissionAssigned(permission.id)) {
      removePermissionMutation.mutate({ roleId: selectedRole.id, permissionId: permission.id });
    } else {
      assignPermissionMutation.mutate({ roleId: selectedRole.id, permissionId: permission.id });
    }
  };

  const openEditModal = (role: Role) => {
    setSelectedRole(role);
    setEditDescription(role.description || '');
    setIsEditModalOpen(true);
  };

  const openDeleteModal = (role: Role) => {
    setSelectedRole(role);
    setIsDeleteModalOpen(true);
  };

  const openPermissionsModal = (role: Role) => {
    setSelectedRole(role);
    setIsPermissionsModalOpen(true);
  };

  if (!tenantId) {
    return (
      <div className="p-6">
        <p className="text-[var(--color-text-secondary)]">Loading tenant information...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Organization Roles</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Manage custom roles and permissions for your organization
          </p>
        </div>
        <Button onClick={() => setIsCreateModalOpen(true)}>
          <Plus size={16} className="mr-2" />
          Create Role
        </Button>
      </div>

      {isLoading && <LoadingBar />}

      <div className="grid gap-4">
        {roles.length === 0 && !isLoading ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Shield className="mx-auto h-12 w-12 text-[var(--color-text-tertiary)]" />
              <h3 className="mt-4 text-lg font-medium text-[var(--color-text-primary)]">No roles defined</h3>
              <p className="mt-2 text-[var(--color-text-secondary)]">
                Create custom roles to control access within your organization
              </p>
              <Button className="mt-4" onClick={() => setIsCreateModalOpen(true)}>
                <Plus size={16} className="mr-2" />
                Create First Role
              </Button>
            </CardContent>
          </Card>
        ) : (
          roles.map((role) => (
            <Card key={role.id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-2 rounded-lg bg-[var(--color-primary)]/10">
                      <Shield className="h-5 w-5 text-[var(--color-primary)]" />
                    </div>
                    <div>
                      <h3 className="font-medium text-[var(--color-text-primary)]">{role.name}</h3>
                      {role.description && (
                        <p className="text-sm text-[var(--color-text-secondary)]">{role.description}</p>
                      )}
                    </div>
                    {role.is_system && (
                      <Badge variant="secondary">System</Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" onClick={() => openPermissionsModal(role)}>
                      <Key size={16} className="mr-1" />
                      Permissions
                    </Button>
                    {!role.is_system && (
                      <>
                        <Button variant="ghost" size="sm" onClick={() => openEditModal(role)}>
                          <Edit size={16} />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => openDeleteModal(role)}>
                          <Trash2 size={16} className="text-red-500" />
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Create Role Modal */}
      <Modal
        isOpen={isCreateModalOpen}
        onClose={() => {
          setIsCreateModalOpen(false);
          setNewRoleName('');
          setNewRoleDescription('');
        }}
        title="Create Role"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">
              Role Name
            </label>
            <Input
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
              placeholder="e.g., Editor, Viewer, Manager"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">
              Description (optional)
            </label>
            <Input
              value={newRoleDescription}
              onChange={(e) => setNewRoleDescription(e.target.value)}
              placeholder="Describe what this role can do"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => setIsCreateModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateRole} disabled={createRoleMutation.isPending}>
              {createRoleMutation.isPending ? 'Creating...' : 'Create Role'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Edit Role Modal */}
      <Modal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false);
          setSelectedRole(null);
        }}
        title="Edit Role"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">
              Role Name
            </label>
            <Input value={selectedRole?.name || ''} disabled className="bg-[var(--color-bg-secondary)]" />
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1">
              Description
            </label>
            <Input
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
              placeholder="Describe what this role can do"
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => setIsEditModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleEditRole} disabled={updateRoleMutation.isPending}>
              {updateRoleMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedRole(null);
        }}
        onConfirm={handleDeleteRole}
        title="Delete Role"
        message={`Are you sure you want to delete the role "${selectedRole?.name}"? Users with this role will lose their associated permissions.`}
        confirmLabel={deleteRoleMutation.isPending ? 'Deleting...' : 'Delete Role'}
        variant="danger"
      />

      {/* Permissions Modal */}
      <Modal
        isOpen={isPermissionsModalOpen}
        onClose={() => {
          setIsPermissionsModalOpen(false);
          setSelectedRole(null);
        }}
        title={`Permissions for ${selectedRole?.name || 'Role'}`}
      >
        <div className="space-y-4 max-h-96 overflow-y-auto">
          {allPermissions.length === 0 ? (
            <p className="text-[var(--color-text-secondary)] text-center py-4">
              No permissions available
            </p>
          ) : (
            allPermissions.map((permission: Permission) => (
              <div
                key={permission.id}
                className="flex items-center justify-between p-3 rounded-lg border border-[var(--color-border)] hover:bg-[var(--color-bg-secondary)] transition-colors"
              >
                <div>
                  <p className="font-medium text-[var(--color-text-primary)]">{permission.name}</p>
                  {permission.description && (
                    <p className="text-sm text-[var(--color-text-secondary)]">{permission.description}</p>
                  )}
                </div>
                <Button
                  variant={isPermissionAssigned(permission.id) ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => handleTogglePermission(permission)}
                  disabled={assignPermissionMutation.isPending || removePermissionMutation.isPending}
                >
                  {isPermissionAssigned(permission.id) ? (
                    <>
                      <Check size={14} className="mr-1" />
                      Assigned
                    </>
                  ) : (
                    <>
                      <Plus size={14} className="mr-1" />
                      Assign
                    </>
                  )}
                </Button>
              </div>
            ))
          )}
        </div>
        <div className="flex justify-end pt-4 border-t border-[var(--color-border)] mt-4">
          <Button variant="outline" onClick={() => setIsPermissionsModalOpen(false)}>
            Close
          </Button>
        </div>
      </Modal>
    </div>
  );
}

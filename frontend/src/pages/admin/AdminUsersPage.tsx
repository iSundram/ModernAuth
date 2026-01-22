import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users,
  Plus,
  Search,
  Mail,
  Shield,
  Trash2,
  CheckCircle,
  XCircle,
  Edit,
  Key,
} from 'lucide-react';
import { Button, Input, Card, CardContent, CardHeader, Modal, Badge, ConfirmDialog, Select } from '../../components/ui';
import type { User, UserRole, Role } from '../../types';
import { userService, adminService } from '../../api/services';
import { useAuth } from '../../hooks/useAuth';
import { useToast } from '../../components/ui/Toast';

const StatusBadge = ({ isActive, isEmailVerified }: { isActive?: boolean; isEmailVerified?: boolean }) => {
  if (!isActive) {
    return (
      <Badge variant="error" size="sm">
        <XCircle size={12} className="mr-1" />
        Inactive
      </Badge>
    );
  }
  
  return (
    <Badge variant={isEmailVerified ? 'success' : 'warning'} size="sm">
      <CheckCircle size={12} className="mr-1" />
      {isEmailVerified ? 'Verified' : 'Unverified'}
    </Badge>
  );
};

const RoleBadge = ({ role }: { role?: UserRole }) => {
  if (!role) return <Badge variant="default" size="sm">User</Badge>;

  return (
    <Badge variant={role === 'admin' ? 'error' : 'default'} size="sm">
      {role === 'admin' && <Shield size={12} className="mr-1" />}
      {role.charAt(0).toUpperCase() + role.slice(1)}
    </Badge>
  );
};

export function AdminUsersPage() {
  const { user: currentUser } = useAuth();
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | UserRole>('all');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false);

  // Fetch users
  const { data: users = [], isLoading: usersLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => userService.list(),
  });

  // Fetch roles
  const { data: roles = [] } = useQuery({
    queryKey: ['roles'],
    queryFn: () => adminService.listRoles(),
  });

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: (id: string) => userService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      showToast({ title: 'Success', message: 'User deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedUser(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete user', type: 'error' });
    },
  });

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<User> }) => userService.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      showToast({ title: 'Success', message: 'User updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedUser(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update user', type: 'error' });
    },
  });

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: (data: { email: string; password: string; username?: string }) => userService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      showToast({ title: 'Success', message: 'User created successfully', type: 'success' });
      setIsCreateModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create user', type: 'error' });
    },
  });

  // Assign role mutation
  const assignRoleMutation = useMutation({
    mutationFn: ({ userId, roleId }: { userId: string; roleId: string }) => 
      adminService.assignRole(userId, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      showToast({ title: 'Success', message: 'Role assigned successfully', type: 'success' });
      setIsRoleModalOpen(false);
      setSelectedUser(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to assign role', type: 'error' });
    },
  });

  const filteredUsers = users.filter((user) => {
    const matchesSearch =
      (user.username?.toLowerCase() || '').includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = roleFilter === 'all' || user.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const activeUsers = users.filter(u => u.is_active).length;
  const adminUsers = users.filter(u => u.role === 'admin').length;
  const verifiedUsers = users.filter(u => u.is_email_verified).length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">User Management</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Manage user accounts, roles, and permissions
          </p>
        </div>
        <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
          Add User
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20">
              <Users size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{users.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Users</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{activeUsers}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Active</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-red-500/10">
              <Shield size={24} className="text-red-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{adminUsers}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Admins</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-blue-500/10">
              <Mail size={24} className="text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{verifiedUsers}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Verified</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search and Filter */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search users by name or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                leftIcon={<Search size={18} />}
              />
            </div>
            <div className="flex gap-2">
              <Button
                variant={roleFilter === 'all' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setRoleFilter('all')}
              >
                All Roles
              </Button>
              <Button
                variant={roleFilter === 'admin' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setRoleFilter('admin')}
              >
                Admin
              </Button>
              <Button
                variant={roleFilter === 'user' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setRoleFilter('user')}
              >
                User
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {/* Users Table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--color-border-light)]">
                  <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    User
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    Role
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    Status
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    Tenant
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    Created
                  </th>
                  <th className="text-right text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                    Actions
                  </th>
                </tr>
              </thead>
                  <tbody className="divide-y divide-[var(--color-border-light)]">
                {usersLoading ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin" />
                        <p className="text-[var(--color-text-secondary)]">Loading users...</p>
                      </div>
                    </td>
                  </tr>
                ) : filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center">
                      <Users size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
                      <p className="text-[var(--color-text-secondary)]">No users found</p>
                      <p className="text-sm text-[var(--color-text-muted)] mt-1">
                        Try adjusting your search or add a new user
                      </p>
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((user) => (
                    <tr
                      key={user.id}
                      className="hover:bg-[var(--color-surface-hover)] transition-colors"
                    >
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-[#B3B3B3] to-[#D4D4D4] flex items-center justify-center">
                            <span className="text-white font-medium text-sm">
                              {(user.username || user.email).charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium text-[var(--color-text-primary)]">
                              {user.username || 'No Username'}
                            </p>
                            <div className="flex items-center gap-1 text-xs text-[var(--color-text-muted)]">
                              <Mail size={12} />
                              {user.email}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <RoleBadge role={user.role} />
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge isActive={user.is_active} isEmailVerified={user.is_email_verified} />
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-[var(--color-text-secondary)] text-xs">
                          {user.tenant_id ? user.tenant_id : '—'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-[var(--color-text-secondary)]">
                          {new Date(user.created_at).toLocaleDateString()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              updateUserMutation.mutate({
                                id: user.id,
                                data: { is_active: !user.is_active }
                              });
                            }}
                            title={user.is_active ? "Disable User" : "Enable User"}
                            disabled={updateUserMutation.isPending}
                          >
                            {user.is_active ? <XCircle size={16} /> : <CheckCircle size={16} />}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedUser(user);
                              setIsRoleModalOpen(true);
                            }}
                            title="Manage Roles"
                          >
                            <Key size={16} />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedUser(user);
                              setIsEditModalOpen(true);
                            }}
                            title="Edit"
                          >
                            <Edit size={16} />
                          </Button>
                          {user.id !== currentUser?.id && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedUser(user);
                                setIsDeleteModalOpen(true);
                              }}
                              className="text-red-500 hover:text-red-600"
                              title="Delete"
                            >
                              <Trash2 size={16} />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Create User Modal */}
      <CreateUserModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={(data) => createUserMutation.mutate(data)}
        isLoading={createUserMutation.isPending}
      />

      {/* Edit User Modal */}
      {selectedUser && (
        <EditUserModal
          isOpen={isEditModalOpen}
          onClose={() => {
            setIsEditModalOpen(false);
            setSelectedUser(null);
          }}
          user={selectedUser}
          onSubmit={(data) => updateUserMutation.mutate({ id: selectedUser.id, data })}
          isLoading={updateUserMutation.isPending}
        />
      )}

      {/* Role Assignment Modal */}
      {selectedUser && (
        <RoleAssignmentModal
          isOpen={isRoleModalOpen}
          onClose={() => {
            setIsRoleModalOpen(false);
            setSelectedUser(null);
          }}
          user={selectedUser}
          roles={roles}
          onSubmit={(roleId) => assignRoleMutation.mutate({ userId: selectedUser.id, roleId })}
          isLoading={assignRoleMutation.isPending}
        />
      )}

      {/* Delete User Confirmation */}
      {selectedUser && (
        <ConfirmDialog
          isOpen={isDeleteModalOpen}
          onClose={() => {
            setIsDeleteModalOpen(false);
            setSelectedUser(null);
          }}
          onConfirm={() => deleteUserMutation.mutate(selectedUser.id)}
          title="Delete User"
          message={`Are you sure you want to delete user ${selectedUser.username || selectedUser.email}? This action cannot be undone.`}
          confirmText="Delete"
          variant="danger"
        />
      )}
    </div>
  );
}

// Create User Modal Component
function CreateUserModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: { email: string; password: string; username?: string }) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
    setFormData({ username: '', email: '', password: '' });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create New User" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Username (Optional)"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          placeholder="Enter username"
        />
        <Input
          label="Email"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          required
          placeholder="Enter email"
        />
        <Input
          label="Password"
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          required
          placeholder="Enter password (min 8 characters)"
          minLength={8}
        />
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Create User
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Edit User Modal Component
function EditUserModal({
  isOpen,
  onClose,
  user,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: User;
  onSubmit: (data: Partial<User>) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({
    email: user.email,
    username: user.username || '',
    phone: user.phone || '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit User" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Email"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          required
        />
        <Input
          label="Username"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          placeholder="Enter username"
        />
        <Input
          label="Phone"
          value={formData.phone}
          onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
          placeholder="Enter phone number"
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

// Role Assignment Modal Component
function RoleAssignmentModal({
  isOpen,
  onClose,
  user,
  roles,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: User;
  roles: Role[];
  onSubmit: (roleId: string) => void;
  isLoading: boolean;
}) {
  const [selectedRoleId, setSelectedRoleId] = useState<string>('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedRoleId) {
      onSubmit(selectedRoleId);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Assign Role" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            User
          </label>
          <Input value={user.username || user.email} disabled />
        </div>
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Current Role
          </label>
          <Input value={user.role || 'user'} disabled />
        </div>
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Assign Role
          </label>
          <Select
            value={selectedRoleId}
            onChange={(e) => setSelectedRoleId(e.target.value)}
            options={roles.map(role => ({ 
              value: role.id, 
              label: `${role.name}${role.description ? ` - ${role.description}` : ''}` 
            }))}
            placeholder="Select a role"
          />
        </div>
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading} disabled={!selectedRoleId}>
            Assign Role
          </Button>
        </div>
      </form>
    </Modal>
  );
}

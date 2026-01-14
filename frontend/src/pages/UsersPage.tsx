import { useState, useEffect } from 'react';
import {
  Users,
  Plus,
  Search,
  Mail,
  Shield,
  Trash2,
  CheckCircle,
  Clock,
  XCircle,
  Edit,
  Ban,
  AlertTriangle,
} from 'lucide-react';
import { Button, Input, Card, CardContent, CardHeader, Modal } from '../components/ui';
import type { User, UserRole } from '../types';
import { userService, adminService } from '../api/services';
import { useAuth } from '../hooks/useAuth';

interface ExtendedUser extends User {
  domains_count?: number;
  last_login?: string;
}

const StatusBadge = ({ status }: { status?: User['status'] }) => {
  if (!status) return <span className="text-[var(--color-text-muted)] text-xs">Unknown</span>;
  
  const styles = {
    active: 'bg-[var(--color-success)]/10 text-[var(--color-success)] border-[var(--color-success)]/20',
    suspended: 'bg-[var(--color-warning)]/10 text-[var(--color-warning)] border-[var(--color-warning)]/20',
    terminated: 'bg-[var(--color-error)]/10 text-[var(--color-error)] border-[var(--color-error)]/20',
  };

  const icons = {
    active: <CheckCircle size={14} />,
    suspended: <Clock size={14} />,
    terminated: <XCircle size={14} />,
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${styles[status]}`}
    >
      {icons[status]}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
};

const RoleBadge = ({ role }: { role?: UserRole }) => {
  if (!role) return <span className="text-[var(--color-text-muted)] text-xs">User</span>;

  const styles = {
    admin: 'bg-[var(--color-error)]/10 text-[var(--color-error)] border-[var(--color-error)]/20',
    user: 'bg-[var(--color-text-muted)]/10 text-[var(--color-text-muted)] border-[var(--color-text-muted)]/20',
  };

  const icons = {
    admin: <Shield size={14} />,
    user: <Users size={14} />,
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${styles[role]}`}
    >
      {icons[role]}
      {role.charAt(0).toUpperCase() + role.slice(1)}
    </span>
  );
};

export function UsersPage() {
  const { user: currentUser } = useAuth();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'suspended' | 'terminated'>('all');
  const [roleFilter, setRoleFilter] = useState<'all' | UserRole>('all');
  const [users, setUsers] = useState<ExtendedUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<ExtendedUser | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isSuspendModalOpen, setIsSuspendModalOpen] = useState(false);
  const [isTerminateModalOpen, setIsTerminateModalOpen] = useState(false);

  const loadUsers = () => {
    setIsLoading(true);
    userService.list()
      .then(setUsers)
      .catch(console.error)
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const filteredUsers = users.filter((user) => {
    const matchesSearch =
      (user.username?.toLowerCase() || '').includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || user.status === statusFilter;
    const matchesRole = roleFilter === 'all' || user.role === roleFilter;
    return matchesSearch && matchesStatus && matchesRole;
  });

  const handleCreate = async (data: { username: string; email: string; password: string; role: UserRole }) => {
    try {
      // 1. Create the user
      const createdUser = await userService.create({
        username: data.username,
        email: data.email,
        password: data.password,
      });

      // 2. Assign role if different from default or explicitly requested
      if (createdUser && createdUser.id && data.role !== 'user') {
        try {
          const roles = await adminService.listRoles();
          const targetRole = roles.find(r => r.name === data.role);
          
          if (targetRole) {
            await adminService.assignRole(createdUser.id, targetRole.id);
          } else {
             console.warn(`Role '${data.role}' not found in available roles.`);
          }
        } catch (roleError) {
          console.error('Failed to assign role:', roleError);
          // Don't fail the whole operation if just role assignment fails, but alert user
          alert('User created but failed to assign role. Please assign manually.');
        }
      }

      setIsCreateModalOpen(false);
      loadUsers();
    } catch (error: any) {
      console.error('Failed to create user:', error);
      alert(`Failed to create user: ${error.message || 'Unknown error'}`);
    }
  };

  const handleUpdate = async (id: string, data: Partial<User>) => {
    try {
      await userService.update(id, data);
      setIsEditModalOpen(false);
      setSelectedUser(null);
      loadUsers();
    } catch (error) {
      console.error('Failed to update user:', error);
      alert('Failed to update user');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await userService.delete(id);
      setIsDeleteModalOpen(false);
      setSelectedUser(null);
      loadUsers();
    } catch (error) {
      console.error('Failed to delete user:', error);
      alert('Failed to delete user');
    }
  };

  const handleSuspend = async (id: string) => {
    try {
      await userService.update(id, { status: 'suspended' });
      setIsSuspendModalOpen(false);
      setSelectedUser(null);
      loadUsers();
    } catch (error) {
      console.error('Failed to suspend user:', error);
      alert('Failed to suspend user');
    }
  };

  const handleTerminate = async (id: string) => {
    try {
      await userService.update(id, { status: 'terminated' });
      setIsTerminateModalOpen(false);
      setSelectedUser(null);
      loadUsers();
    } catch (error) {
      console.error('Failed to terminate user:', error);
      alert('Failed to terminate user');
    }
  };

  const canManageUsers = currentUser?.role === 'admin';

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Users</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Manage user accounts and permissions
          </p>
        </div>
        {canManageUsers && (
          <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
            Add User
          </Button>
        )}
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
            <div className="p-3 rounded-xl bg-[var(--color-success)]/10">
              <CheckCircle size={24} className="text-[var(--color-success)]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">
                {users.filter((u) => u.status === 'active').length}
              </p>
              <p className="text-sm text-[var(--color-text-secondary)]">Active</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-[var(--color-error)]/10">
              <Shield size={24} className="text-[var(--color-error)]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">
                {users.filter((u) => u.role === 'admin').length}
              </p>
              <p className="text-sm text-[var(--color-text-secondary)]">Admins</p>
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
            <div className="flex gap-2 flex-wrap">
              <Button
                variant={statusFilter === 'all' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setStatusFilter('all')}
              >
                All
              </Button>
              <Button
                variant={statusFilter === 'active' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setStatusFilter('active')}
              >
                Active
              </Button>
              <Button
                variant={statusFilter === 'suspended' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setStatusFilter('suspended')}
              >
                Suspended
              </Button>
              <Button
                variant={statusFilter === 'terminated' ? 'primary' : 'ghost'}
                size="sm"
                onClick={() => setStatusFilter('terminated')}
              >
                Terminated
              </Button>
            </div>
            {currentUser?.role === 'admin' && (
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
            )}
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
                    Created
                  </th>
                  {canManageUsers && (
                    <th className="text-right text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider px-6 py-3">
                      Actions
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-light)]">
                {isLoading ? (
                  <tr>
                    <td colSpan={canManageUsers ? 5 : 4} className="px-6 py-12 text-center">
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin" />
                        <p className="text-[var(--color-text-secondary)]">Loading users...</p>
                      </div>
                    </td>
                  </tr>
                ) : filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={canManageUsers ? 5 : 4} className="px-6 py-12 text-center">
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
                      className="hover:bg-[var(--color-primary-dark)]/30 transition-colors"
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
                        <StatusBadge status={user.status} />
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-[var(--color-text-secondary)]">
                          {new Date(user.created_at).toLocaleDateString()}
                        </span>
                      </td>
                      {canManageUsers && (
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-2">
                            {user.status === 'active' && (
                              <>
                                <button
                                  onClick={() => {
                                    setSelectedUser(user);
                                    setIsSuspendModalOpen(true);
                                  }}
                                  className="p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-warning)] hover:bg-[var(--color-warning)]/10 transition-colors"
                                  title="Suspend"
                                >
                                  <Ban size={16} />
                                </button>
                              </>
                            )}
                            {user.status === 'suspended' && (
                              <button
                                onClick={() => {
                                  setSelectedUser(user);
                                  handleUpdate(user.id, { status: 'active' });
                                }}
                                className="p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-success)] hover:bg-[var(--color-success)]/10 transition-colors"
                                title="Unsuspend"
                              >
                                <CheckCircle size={16} />
                              </button>
                            )}
                            <button
                              onClick={() => {
                                setSelectedUser(user);
                                setIsEditModalOpen(true);
                              }}
                              className="p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-primary-medium)]/20 transition-colors"
                              title="Edit"
                            >
                              <Edit size={16} />
                            </button>
                            {user.id !== currentUser?.id && (
                              <>
                                <button
                                  onClick={() => {
                                    setSelectedUser(user);
                                    setIsTerminateModalOpen(true);
                                  }}
                                  className="p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-error)] hover:bg-[var(--color-error)]/10 transition-colors"
                                  title="Terminate"
                                >
                                  <AlertTriangle size={16} />
                                </button>
                                <button
                                  onClick={() => {
                                    setSelectedUser(user);
                                    setIsDeleteModalOpen(true);
                                  }}
                                  className="p-2 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-error)] hover:bg-[var(--color-error)]/10 transition-colors"
                                  title="Delete"
                                >
                                  <Trash2 size={16} />
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      )}
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
        onSubmit={handleCreate}
      />

      {/* Edit User Modal */}
      {selectedUser && (
        <>
          <EditUserModal
            isOpen={isEditModalOpen}
            onClose={() => {
              setIsEditModalOpen(false);
              setSelectedUser(null);
            }}
            user={selectedUser}
            onSubmit={handleUpdate}
          />
          <DeleteUserModal
            isOpen={isDeleteModalOpen}
            onClose={() => {
              setIsDeleteModalOpen(false);
              setSelectedUser(null);
            }}
            user={selectedUser}
            onConfirm={handleDelete}
          />
          <SuspendUserModal
            isOpen={isSuspendModalOpen}
            onClose={() => {
              setIsSuspendModalOpen(false);
              setSelectedUser(null);
            }}
            user={selectedUser}
            onConfirm={handleSuspend}
          />
          <TerminateUserModal
            isOpen={isTerminateModalOpen}
            onClose={() => {
              setIsTerminateModalOpen(false);
              setSelectedUser(null);
            }}
            user={selectedUser}
            onConfirm={handleTerminate}
          />
        </>
      )}
    </div>
  );
}

// Create User Modal Component
function CreateUserModal({
  isOpen,
  onClose,
  onSubmit,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: { username: string; email: string; password: string; role: UserRole }) => void;
}) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    role: 'user' as UserRole,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await onSubmit(formData);
      setFormData({ username: '', email: '', password: '', role: 'user' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create New User" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Username"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          required
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
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Role
          </label>
          <select
            value={formData.role}
            onChange={(e) => setFormData({ ...formData, role: e.target.value as UserRole })}
            className="w-full px-4 py-2 rounded-lg bg-[var(--color-primary-dark)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
          >
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isSubmitting}>
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
}: {
  isOpen: boolean;
  onClose: () => void;
  user: ExtendedUser;
  onSubmit: (id: string, data: Partial<User>) => void;
}) {
  const [formData, setFormData] = useState({
    email: user.email,
    role: user.role || 'user',
    status: user.status || 'active',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    setFormData({
      email: user.email,
      role: user.role || 'user',
      status: user.status || 'active',
    });
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await onSubmit(user.id, formData);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit User" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Username
          </label>
          <Input value={user.username || 'No Username'} disabled />
        </div>
        <Input
          label="Email"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          required
        />
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Role
          </label>
          <select
            value={formData.role}
            onChange={(e) => setFormData({ ...formData, role: e.target.value as UserRole })}
            className="w-full px-4 py-2 rounded-lg bg-[var(--color-primary-dark)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
          >
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Status
          </label>
          <select
            value={formData.status}
            onChange={(e) =>
              setFormData({ ...formData, status: e.target.value as any })
            }
            className="w-full px-4 py-2 rounded-lg bg-[var(--color-primary-dark)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
          >
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="terminated">Terminated</option>
          </select>
        </div>
        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isSubmitting}>
            Save Changes
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Delete User Modal Component
function DeleteUserModal({
  isOpen,
  onClose,
  user,
  onConfirm,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: ExtendedUser;
  onConfirm: (id: string) => void;
}) {
  const [isDeleting, setIsDeleting] = useState(false);

  const handleConfirm = async () => {
    setIsDeleting(true);
    try {
      await onConfirm(user.id);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Delete User" size="md">
      <div className="space-y-4">
        <div className="p-4 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20">
          <p className="text-[var(--color-text-primary)]">
            Are you sure you want to delete user <strong>{user.username}</strong>?
          </p>
          <p className="text-sm text-[var(--color-text-secondary)] mt-2">
            This action cannot be undone. All user data will be permanently deleted.
          </p>
        </div>
        <div className="flex gap-3 pt-4">
          <Button variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleConfirm}
            className="flex-1 bg-[var(--color-error)] hover:bg-[var(--color-error)]/90"
            isLoading={isDeleting}
          >
            Delete User
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// Suspend User Modal Component
function SuspendUserModal({
  isOpen,
  onClose,
  user,
  onConfirm,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: ExtendedUser;
  onConfirm: (id: string) => void;
}) {
  const [isSuspending, setIsSuspending] = useState(false);

  const handleConfirm = async () => {
    setIsSuspending(true);
    try {
      await onConfirm(user.id);
    } finally {
      setIsSuspending(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Suspend User" size="md">
      <div className="space-y-4">
        <div className="p-4 rounded-lg bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/20">
          <p className="text-[var(--color-text-primary)]">
            Are you sure you want to suspend user <strong>{user.username}</strong>?
          </p>
          <p className="text-sm text-[var(--color-text-secondary)] mt-2">
            The user will not be able to access their account until unsuspended.
          </p>
        </div>
        <div className="flex gap-3 pt-4">
          <Button variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleConfirm}
            className="flex-1 bg-[var(--color-warning)] hover:bg-[var(--color-warning)]/90"
            isLoading={isSuspending}
          >
            Suspend User
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// Terminate User Modal Component
function TerminateUserModal({
  isOpen,
  onClose,
  user,
  onConfirm,
}: {
  isOpen: boolean;
  onClose: () => void;
  user: ExtendedUser;
  onConfirm: (id: string) => void;
}) {
  const [isTerminating, setIsTerminating] = useState(false);

  const handleConfirm = async () => {
    setIsTerminating(true);
    try {
      await onConfirm(user.id);
    } finally {
      setIsTerminating(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Terminate User" size="md">
      <div className="space-y-4">
        <div className="p-4 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20">
          <p className="text-[var(--color-text-primary)]">
            Are you sure you want to terminate user <strong>{user.username}</strong>?
          </p>
          <p className="text-sm text-[var(--color-text-secondary)] mt-2">
            The user account will be marked as terminated. This is different from deletion - the account data will be preserved but access will be revoked.
          </p>
        </div>
        <div className="flex gap-3 pt-4">
          <Button variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleConfirm}
            className="flex-1 bg-[var(--color-error)] hover:bg-[var(--color-error)]/90"
            isLoading={isTerminating}
          >
            Terminate User
          </Button>
        </div>
      </div>
    </Modal>
  );
}
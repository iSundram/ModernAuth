import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  User,
  Mail,
  Phone,
  Save,
  Trash2,
  AlertTriangle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Input, Badge } from '../../components/ui';
import { userService, authService } from '../../api/services';
import { useAuth } from '../../hooks/useAuth';
import { useToast } from '../../components/ui/Toast';
import type { UpdateUserRequest } from '../../types';

export function UserSettingsPage() {
  const { user, setUser } = useAuth();
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const [formData, setFormData] = useState<UpdateUserRequest>({
    email: user?.email || '',
    username: user?.username || '',
    phone: user?.phone || '',
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    avatar_url: user?.avatar_url || '',
    timezone: user?.timezone || 'UTC',
    locale: user?.locale || 'en',
  });

  // Delete account state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: (data: UpdateUserRequest) => {
      if (!user?.id) throw new Error('User not found');
      return userService.update(user.id, data);
    },
    onSuccess: (updatedUser) => {
      setUser(updatedUser);
      queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
      showToast({ title: 'Success', message: 'Profile updated successfully', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update profile', type: 'error' });
    },
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    updateUserMutation.mutate(formData);
  };

  // Delete own account mutation
  const deleteAccountMutation = useMutation({
    mutationFn: (password: string) => authService.deleteAccount(password),
    onSuccess: () => {
      showToast({ title: 'Account Deleted', message: 'Your account has been permanently deleted.', type: 'success' });
      // Clear auth state and redirect
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete account', type: 'error' });
    },
  });

  const handleDeleteAccount = () => {
    if (deleteConfirmText !== 'DELETE' || !deletePassword) return;
    deleteAccountMutation.mutate(deletePassword);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Account Settings</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Manage your account information and preferences.
        </p>
      </div>

      {/* Profile Information */}
      <Card>
        <CardHeader>
          <CardTitle>Profile Information</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input
                label="First Name"
                value={formData.first_name || ''}
                onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
                placeholder="John"
                leftIcon={<User size={18} />}
              />
              <Input
                label="Last Name"
                value={formData.last_name || ''}
                onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
                placeholder="Doe"
                leftIcon={<User size={18} />}
              />
            </div>

            <Input
              label="Email"
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
              leftIcon={<Mail size={18} />}
            />

            <Input
              label="Username"
              value={formData.username || ''}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              placeholder="johndoe"
              leftIcon={<User size={18} />}
            />

            <Input
              label="Phone"
              type="tel"
              value={formData.phone || ''}
              onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
              placeholder="+1234567890"
              leftIcon={<Phone size={18} />}
            />

            <Input
              label="Avatar URL"
              type="url"
              value={formData.avatar_url || ''}
              onChange={(e) => setFormData({ ...formData, avatar_url: e.target.value })}
              placeholder="https://example.com/avatar.jpg"
            />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
                  Timezone
                </label>
                <select
                  value={formData.timezone}
                  onChange={(e) => setFormData({ ...formData, timezone: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
                >
                  <option value="UTC">UTC</option>
                  <option value="America/New_York">America/New_York (EST)</option>
                  <option value="America/Chicago">America/Chicago (CST)</option>
                  <option value="America/Denver">America/Denver (MST)</option>
                  <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
                  <option value="Europe/London">Europe/London (GMT)</option>
                  <option value="Europe/Paris">Europe/Paris (CET)</option>
                  <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                  <option value="Asia/Shanghai">Asia/Shanghai (CST)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
                  Locale
                </label>
                <select
                  value={formData.locale}
                  onChange={(e) => setFormData({ ...formData, locale: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[#D4D4D4]"
                >
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                  <option value="de">German</option>
                  <option value="ja">Japanese</option>
                  <option value="zh">Chinese</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-[var(--color-border-light)]">
              <div className="text-sm text-[var(--color-text-muted)]">
                {user?.is_email_verified ? (
                  <Badge variant="success" size="sm">
                    <Mail size={12} className="mr-1" />
                    Email Verified
                  </Badge>
                ) : (
                  <Badge variant="warning" size="sm">
                    <Mail size={12} className="mr-1" />
                    Email Not Verified
                  </Badge>
                )}
              </div>
              <Button
                type="submit"
                variant="primary"
                leftIcon={<Save size={18} />}
                isLoading={updateUserMutation.isPending}
              >
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Account Information (Read-only) */}
      <Card>
        <CardHeader>
          <CardTitle>Account Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
            <span className="text-sm text-[var(--color-text-secondary)]">User ID</span>
            <span className="text-sm font-mono text-[var(--color-text-primary)]">{user?.id}</span>
          </div>
          <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
            <span className="text-sm text-[var(--color-text-secondary)]">Role</span>
            <Badge variant="default" size="sm" className="capitalize">
              {user?.role || 'user'}
            </Badge>
          </div>
          <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
            <span className="text-sm text-[var(--color-text-secondary)]">Account Status</span>
            <Badge variant={user?.is_active ? 'success' : 'error'} size="sm">
              {user?.is_active ? 'Active' : 'Inactive'}
            </Badge>
          </div>
          <div className="flex justify-between py-2 border-b border-[var(--color-border-light)]">
            <span className="text-sm text-[var(--color-text-secondary)]">Member Since</span>
            <span className="text-sm text-[var(--color-text-primary)]">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
            </span>
          </div>
          {user?.last_login_at && (
            <div className="flex justify-between py-2">
              <span className="text-sm text-[var(--color-text-secondary)]">Last Login</span>
              <span className="text-sm text-[var(--color-text-primary)]">
                {new Date(user.last_login_at).toLocaleString()}
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Danger Zone - Account Deletion */}
      <Card className="border-red-500/30">
        <CardHeader>
          <CardTitle className="text-red-500 flex items-center gap-2">
            <AlertTriangle size={20} />
            Danger Zone
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="text-sm font-medium text-[var(--color-text-primary)]">Delete Account</h3>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">
              Permanently delete your account and all associated data. This action cannot be undone.
            </p>
          </div>

          {!showDeleteConfirm ? (
            <Button
              variant="outline"
              className="border-red-500/50 text-red-500 hover:bg-red-500/10"
              leftIcon={<Trash2 size={16} />}
              onClick={() => setShowDeleteConfirm(true)}
            >
              Delete My Account
            </Button>
          ) : (
            <div className="space-y-4 p-4 rounded-lg bg-red-500/5 border border-red-500/20">
              <p className="text-sm text-red-400 font-medium">
                This will permanently delete your account, including all your data, sessions, and settings.
              </p>
              <Input
                label="Enter your password to confirm"
                type="password"
                value={deletePassword}
                onChange={(e) => setDeletePassword(e.target.value)}
                placeholder="Your current password"
              />
              <Input
                label='Type "DELETE" to confirm'
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder="DELETE"
              />
              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowDeleteConfirm(false);
                    setDeletePassword('');
                    setDeleteConfirmText('');
                  }}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  className="bg-red-600 hover:bg-red-700"
                  leftIcon={<Trash2 size={16} />}
                  onClick={handleDeleteAccount}
                  isLoading={deleteAccountMutation.isPending}
                  disabled={deleteConfirmText !== 'DELETE' || !deletePassword}
                >
                  Permanently Delete Account
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

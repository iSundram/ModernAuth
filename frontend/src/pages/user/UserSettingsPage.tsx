import { useState, useEffect, useMemo, useCallback } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  User,
  Mail,
  Phone,
  Save,
  Trash2,
  AlertTriangle,
  Settings,
  Bell,
  Palette,
  Shield,
  UserCog,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Input, Badge, AvatarUpload } from '../../components/ui';
import { TimezoneSelect } from '../../components/ui/TimezoneSelect';
import { LocaleSelect } from '../../components/ui/LocaleSelect';
import { authService } from '../../api/services';
import { useAuth } from '../../hooks/useAuth';
import { useUpdateProfile } from '../../hooks/usePreferences';
import { useToast } from '../../components/ui/Toast';
import { NotificationPreferencesCard, AppearanceSettingsCard, PrivacySettingsCard } from '../../components/settings';
import type { UpdateProfileRequest } from '../../types';

// Tab definitions
const TABS = [
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'preferences', label: 'Preferences', icon: Settings },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'privacy', label: 'Privacy', icon: Shield },
  { id: 'account', label: 'Account', icon: UserCog },
] as const;

type TabId = typeof TABS[number]['id'];

// Validation types
interface ValidationErrors {
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
}

// Validation helpers
function validateEmail(email: string): string | undefined {
  if (!email.trim()) return 'Email is required';
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return 'Please enter a valid email address';
  return undefined;
}

function validateUsername(username: string): string | undefined {
  if (username && (username.length < 3 || username.length > 50)) {
    return 'Username must be between 3 and 50 characters';
  }
  return undefined;
}

function validateName(name: string, field: string): string | undefined {
  if (name && name.length > 100) {
    return `${field} must be 100 characters or less`;
  }
  return undefined;
}

export function UserSettingsPage() {
  const { user, setUser } = useAuth();
  const { showToast } = useToast();
  const updateProfile = useUpdateProfile();

  // Active tab state
  const [activeTab, setActiveTab] = useState<TabId>('profile');

  // Profile form state
  const [formData, setFormData] = useState<UpdateProfileRequest>({
    email: user?.email || '',
    username: user?.username || '',
    phone: user?.phone || '',
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    avatar_url: user?.avatar_url || '',
    timezone: user?.timezone || 'UTC',
    locale: user?.locale || 'en-US',
  });

  // Validation errors
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});

  // Track original values for dirty state
  const originalData = useMemo(() => ({
    email: user?.email || '',
    username: user?.username || '',
    phone: user?.phone || '',
    first_name: user?.first_name || '',
    last_name: user?.last_name || '',
    avatar_url: user?.avatar_url || '',
    timezone: user?.timezone || 'UTC',
    locale: user?.locale || 'en-US',
  }), [user]);

  // Check if form has unsaved changes
  const isDirty = useMemo(() => {
    return Object.keys(formData).some(
      (key) => formData[key as keyof UpdateProfileRequest] !== originalData[key as keyof UpdateProfileRequest]
    );
  }, [formData, originalData]);

  // Validate all fields
  const validateAll = useCallback((): boolean => {
    const newErrors: ValidationErrors = {
      email: validateEmail(formData.email || ''),
      username: validateUsername(formData.username || ''),
      first_name: validateName(formData.first_name || '', 'First name'),
      last_name: validateName(formData.last_name || '', 'Last name'),
    };

    setErrors(newErrors);
    return !Object.values(newErrors).some(Boolean);
  }, [formData]);

  // Validate on blur
  const handleBlur = (field: keyof ValidationErrors) => {
    setTouched((prev) => ({ ...prev, [field]: true }));
    
    let error: string | undefined;
    switch (field) {
      case 'email':
        error = validateEmail(formData.email || '');
        break;
      case 'username':
        error = validateUsername(formData.username || '');
        break;
      case 'first_name':
        error = validateName(formData.first_name || '', 'First name');
        break;
      case 'last_name':
        error = validateName(formData.last_name || '', 'Last name');
        break;
    }
    setErrors((prev) => ({ ...prev, [field]: error }));
  };

  // Update form field
  const updateField = <K extends keyof UpdateProfileRequest>(field: K, value: UpdateProfileRequest[K]) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  // Handle profile save
  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateAll()) return;

    try {
      const updatedUser = await updateProfile.mutateAsync(formData);
      if (updatedUser) {
        setUser(updatedUser);
      }
      showToast({ title: 'Success', message: 'Profile updated successfully', type: 'success' });
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to update profile', 
        type: 'error' 
      });
    }
  };

  // Delete account state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Delete account mutation
  const deleteAccountMutation = useMutation({
    mutationFn: (password: string) => authService.deleteAccount(password),
    onSuccess: () => {
      showToast({ title: 'Account Deleted', message: 'Your account has been permanently deleted.', type: 'success' });
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

  // Warn about unsaved changes when switching tabs
  const handleTabChange = (tabId: TabId) => {
    if (isDirty && activeTab === 'profile') {
      const confirmed = window.confirm('You have unsaved changes. Are you sure you want to leave?');
      if (!confirmed) return;
    }
    setActiveTab(tabId);
  };

  // Warn before leaving page with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isDirty]);

  // Render tab content
  const renderTabContent = () => {
    switch (activeTab) {
      case 'profile':
        return (
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleProfileSave} className="space-y-6">
                {/* Avatar */}
                <div className="flex justify-center pb-4 border-b border-[var(--color-border-light)]">
                  <AvatarUpload
                    currentUrl={formData.avatar_url}
                    name={`${formData.first_name || ''} ${formData.last_name || ''}`.trim()}
                    onUpload={(url) => updateField('avatar_url', url)}
                    onRemove={() => updateField('avatar_url', '')}
                  />
                </div>

                {/* Name fields */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Input
                    label="First Name"
                    value={formData.first_name || ''}
                    onChange={(e) => updateField('first_name', e.target.value)}
                    onBlur={() => handleBlur('first_name')}
                    placeholder="John"
                    leftIcon={<User size={18} />}
                    error={touched.first_name ? errors.first_name : undefined}
                  />
                  <Input
                    label="Last Name"
                    value={formData.last_name || ''}
                    onChange={(e) => updateField('last_name', e.target.value)}
                    onBlur={() => handleBlur('last_name')}
                    placeholder="Doe"
                    leftIcon={<User size={18} />}
                    error={touched.last_name ? errors.last_name : undefined}
                  />
                </div>

                {/* Email */}
                <Input
                  label="Email"
                  type="email"
                  value={formData.email || ''}
                  onChange={(e) => updateField('email', e.target.value)}
                  onBlur={() => handleBlur('email')}
                  required
                  leftIcon={<Mail size={18} />}
                  error={touched.email ? errors.email : undefined}
                />

                {/* Username */}
                <Input
                  label="Username"
                  value={formData.username || ''}
                  onChange={(e) => updateField('username', e.target.value)}
                  onBlur={() => handleBlur('username')}
                  placeholder="johndoe"
                  leftIcon={<User size={18} />}
                  helperText="3-50 characters"
                  error={touched.username ? errors.username : undefined}
                />

                {/* Phone */}
                <Input
                  label="Phone"
                  type="tel"
                  value={formData.phone || ''}
                  onChange={(e) => updateField('phone', e.target.value)}
                  placeholder="+1234567890"
                  leftIcon={<Phone size={18} />}
                />

                {/* Save button */}
                <div className="flex items-center justify-between pt-4 border-t border-[var(--color-border-light)]">
                  <div className="flex items-center gap-2">
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
                    {isDirty && (
                      <span className="text-sm text-amber-600">Unsaved changes</span>
                    )}
                  </div>
                  <Button
                    type="submit"
                    variant="primary"
                    leftIcon={<Save size={18} />}
                    isLoading={updateProfile.isPending}
                    disabled={!isDirty || Object.values(errors).some(Boolean)}
                  >
                    Save Changes
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        );

      case 'preferences':
        return (
          <Card>
            <CardHeader>
              <CardTitle>Preferences</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="relative">
                <TimezoneSelect
                  value={formData.timezone || 'UTC'}
                  onChange={(tz) => {
                    updateField('timezone', tz);
                    // Auto-save preferences
                    updateProfile.mutate({ ...formData, timezone: tz });
                  }}
                  label="Timezone"
                  helperText="Your local timezone for date and time display"
                />
              </div>

              <LocaleSelect
                value={formData.locale || 'en-US'}
                onChange={(locale) => {
                  updateField('locale', locale);
                  // Auto-save preferences
                  updateProfile.mutate({ ...formData, locale });
                }}
                label="Language"
              />
            </CardContent>
          </Card>
        );

      case 'notifications':
        return <NotificationPreferencesCard />;

      case 'appearance':
        return <AppearanceSettingsCard />;

      case 'privacy':
        return <PrivacySettingsCard />;

      case 'account':
        return (
          <div className="space-y-6">
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

            {/* Danger Zone */}
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

      default:
        return null;
    }
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

      {/* Tab Navigation */}
      <div className="border-b border-[var(--color-border)]">
        <nav className="flex space-x-1 overflow-x-auto" aria-label="Settings tabs">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`
                  flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap
                  border-b-2 transition-colors duration-200
                  ${isActive
                    ? 'border-[var(--color-info)] text-[var(--color-info)]'
                    : 'border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border)]'
                  }
                `}
                aria-current={isActive ? 'page' : undefined}
              >
                <Icon size={18} />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {renderTabContent()}
      </div>
    </div>
  );
}

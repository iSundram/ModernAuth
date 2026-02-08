import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  Shield,
  Save,
  RefreshCw,
  Eye,
  EyeOff,
  Building2,
  Mail,
  Search,
  RotateCcw,
  AlertCircle,
  Clock,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button, Input, LoadingBar, ConfirmDialog } from '../../components/ui';
import { adminService } from '../../api/services';
import { useToast } from '../../components/ui/Toast';
import type { SystemSetting } from '../../types';

// Default values for settings (used for "Reset to Default" and "Modified" badge)
const DEFAULT_SETTING_VALUES: Record<string, unknown> = {
  'site.name': 'ModernAuth',
  'site.logo_url': '',
  'auth.allow_registration': true,
  'auth.require_email_verification': true,
  'auth.mfa_enabled': false,
  'email.provider': 'smtp',
  'email.from_name': 'ModernAuth',
  'email.from_email': 'noreply@example.com',
  'email.smtp_host': 'localhost',
  'email.smtp_port': 587,
  'email.smtp_user': '',
  'email.smtp_password': '',
};

// Security-sensitive settings that require confirmation
const SECURITY_SENSITIVE_SETTINGS = [
  'auth.allow_registration',
  'auth.require_email_verification',
  'auth.mfa_enabled',
];

// Category metadata with icons and descriptions
const CATEGORY_META = {
  general: {
    icon: Building2,
    label: 'General',
    description: 'Site name, branding, and basic configuration',
  },
  auth: {
    icon: Shield,
    label: 'Authentication',
    description: 'Security, MFA, and registration settings',
  },
  email: {
    icon: Mail,
    label: 'Email (SMTP)',
    description: 'Email provider and SMTP configuration',
  },
};

// Validation functions
const validateEmail = (email: string): string | null => {
  if (!email) return null;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) ? null : 'Invalid email format';
};

const validateUrl = (url: string): string | null => {
  if (!url) return null;
  try {
    new URL(url);
    return null;
  } catch {
    return 'Invalid URL format';
  }
};

const validatePort = (port: number): string | null => {
  if (port < 1 || port > 65535) {
    return 'Port must be between 1 and 65535';
  }
  return null;
};

// Validation rules by setting key
const VALIDATION_RULES: Record<string, (value: unknown) => string | null> = {
  'email.from_email': (v) => validateEmail(String(v)),
  'site.logo_url': (v) => validateUrl(String(v)),
  'email.smtp_port': (v) => validatePort(Number(v)),
};

export function AdminSettingsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'general' | 'auth' | 'email'>('general');
  const [localSettings, setLocalSettings] = useState<Record<string, unknown>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [validationErrors, setValidationErrors] = useState<Record<string, string | null>>({});
  
  // Confirmation dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    settingKey: string;
    newValue: unknown;
    title: string;
    message: string;
  }>({
    isOpen: false,
    settingKey: '',
    newValue: null,
    title: '',
    message: '',
  });

  // Fetch settings
  const { data: settingsData = [], isLoading: settingsLoading } = useQuery({
    queryKey: ['admin-settings'],
    queryFn: () => adminService.listSettings(),
  });

  const settings = useMemo(() => Array.isArray(settingsData) ? settingsData : [], [settingsData]);

  // Fetch service status
  const { data: servicesData = [] } = useQuery({
    queryKey: ['admin-services'],
    queryFn: () => adminService.getServiceStatus(),
  });

  const services = Array.isArray(servicesData) ? servicesData : [];

  // Fetch system stats
  const { data: systemStats } = useQuery({
    queryKey: ['admin-stats'],
    queryFn: () => adminService.getSystemStats(),
  });

  const mergedSettings = useMemo(() => {
    const initialSettings: Record<string, unknown> = {};
    if (settings && settings.length > 0) {
      settings.forEach(s => {
        if (s && s.key) {
          initialSettings[s.key] = s.value;
        }
      });
    }
    return { ...initialSettings, ...localSettings };
  }, [settings, localSettings]);

  // Check if a setting matches current search
  const isSettingVisible = useCallback((key: string) => {
    if (!searchQuery.trim()) return true;
    const setting = settings.find(s => s.key === key);
    if (!setting) return false;
    const query = searchQuery.toLowerCase();
    return setting.key.toLowerCase().includes(query) || 
           setting.description.toLowerCase().includes(query);
  }, [settings, searchQuery]);

  // Get settings count per category that match search
  const getCategoryMatchCount = useCallback((category: 'general' | 'auth' | 'email') => {
    const categorySettings: Record<string, string[]> = {
      general: ['site.name', 'site.logo_url'],
      auth: ['auth.allow_registration', 'auth.require_email_verification', 'auth.mfa_enabled'],
      email: ['email.provider', 'email.from_name', 'email.from_email', 'email.smtp_host', 'email.smtp_port', 'email.smtp_user', 'email.smtp_password'],
    };
    return categorySettings[category].filter(key => isSettingVisible(key)).length;
  }, [isSettingVisible]);

  // Get pending changes (local settings that differ from server settings)
  const pendingChanges = useMemo(() => {
    const changes: { key: string; value: unknown }[] = [];
    Object.entries(localSettings).forEach(([key, value]) => {
      const serverSetting = settings.find(s => s.key === key);
      if (serverSetting && serverSetting.value !== value && !validationErrors[key]) {
        changes.push({ key, value });
      }
    });
    return changes;
  }, [localSettings, settings, validationErrors]);

  // Save all pending changes
  const handleSaveAllChanges = async () => {
    if (pendingChanges.length === 0) return;
    
    for (const change of pendingChanges) {
      try {
        await adminService.updateSetting(change.key, change.value);
      } catch (error) {
        let errorMessage = `Failed to update ${change.key}`;
        if (error instanceof Error) {
          errorMessage = error.message;
        }
        showToast({ title: 'Error', message: errorMessage, type: 'error' });
        return; // Stop on first error
      }
    }
    
    // Clear all local settings and refresh
    setLocalSettings({});
    queryClient.invalidateQueries({ queryKey: ['admin-settings'] });
    showToast({ title: 'Success', message: `${pendingChanges.length} setting(s) updated successfully`, type: 'success' });
  };

  // Update setting mutation
  const updateSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: unknown }) => adminService.updateSetting(key, value),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['admin-settings'] });
      // Clear local setting after successful save
      setLocalSettings(prev => {
        const next = { ...prev };
        delete next[variables.key];
        return next;
      });
      showToast({ title: 'Success', message: 'Setting updated successfully', type: 'success' });
    },
    onError: (error: unknown) => {
      // Parse error response properly
      let errorMessage = 'Failed to update setting';
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'object' && error !== null) {
        const errorObj = error as { response?: { data?: { message?: string; error?: string } }; message?: string };
        errorMessage = errorObj.response?.data?.message || errorObj.response?.data?.error || errorObj.message || errorMessage;
      }
      showToast({ title: 'Error', message: errorMessage, type: 'error' });
    },
  });

  const handleUpdate = (key: string) => {
    if (mergedSettings[key] !== undefined) {
      updateSettingMutation.mutate({ key, value: mergedSettings[key] });
    }
  };

  const handleInputChange = (key: string, value: unknown, type?: 'text' | 'number' | 'boolean' | 'password') => {
    // For number type, ensure we store as number
    let processedValue = value;
    if (type === 'number') {
      processedValue = typeof value === 'string' ? (parseInt(value, 10) || 0) : value;
    }
    
    setLocalSettings(prev => ({ ...prev, [key]: processedValue }));
    
    // Run validation if there's a rule for this key
    if (VALIDATION_RULES[key]) {
      const error = VALIDATION_RULES[key](processedValue);
      setValidationErrors(prev => ({ ...prev, [key]: error }));
    }
  };

  const handleBooleanToggle = (key: string, currentValue: unknown) => {
    const newValue = !currentValue;
    
    // Check if this is a security-sensitive setting
    if (SECURITY_SENSITIVE_SETTINGS.includes(key)) {
      const setting = settings.find(s => s.key === key);
      setConfirmDialog({
        isOpen: true,
        settingKey: key,
        newValue,
        title: 'Confirm Security Setting Change',
        message: `You are about to ${newValue ? 'enable' : 'disable'} "${setting?.description || key}". This change affects your application's security. Are you sure you want to proceed?`,
      });
    } else {
      handleInputChange(key, newValue);
      updateSettingMutation.mutate({ key, value: newValue });
    }
  };

  const handleConfirmSecurityChange = () => {
    const { settingKey, newValue } = confirmDialog;
    handleInputChange(settingKey, newValue);
    updateSettingMutation.mutate({ key: settingKey, value: newValue });
    setConfirmDialog(prev => ({ ...prev, isOpen: false }));
  };

  const handleResetToDefault = (key: string) => {
    const defaultValue = DEFAULT_SETTING_VALUES[key];
    if (defaultValue !== undefined) {
      handleInputChange(key, defaultValue);
      updateSettingMutation.mutate({ key, value: defaultValue });
    }
  };

  const toggleSecret = (key: string) => {
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Check if a setting differs from its default
  const isDifferentFromDefault = (key: string, currentValue: unknown): boolean => {
    const defaultValue = DEFAULT_SETTING_VALUES[key];
    return defaultValue !== undefined && currentValue !== defaultValue;
  };

  // Format relative time for last updated
  const formatRelativeTime = (dateString: string): string => {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const renderSettingRow = (key: string, type: 'text' | 'number' | 'boolean' | 'password' = 'text') => {
    if (!Array.isArray(settings)) return null;
    
    // Skip if not visible in search
    if (!isSettingVisible(key)) return null;
    
    const setting = settings.find(s => s.key === key) as SystemSetting | undefined;
    if (!setting) return null;

    const currentValue = mergedSettings[key] !== undefined ? mergedSettings[key] : setting.value;
    const hasChanged = currentValue !== setting.value;
    const isModified = isDifferentFromDefault(key, currentValue);
    const validationError = validationErrors[key];
    const hasResetOption = DEFAULT_SETTING_VALUES[key] !== undefined;

    return (
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 py-4 border-b border-[var(--color-border-light)] last:border-0">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium text-[var(--color-text-primary)]">{setting.key}</p>
            {isModified && (
              <Badge variant="warning" size="sm">Modified</Badge>
            )}
          </div>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">{setting.description}</p>
          <div className="flex items-center gap-2 mt-2 text-xs text-[var(--color-text-muted)]">
            <Clock size={12} />
            <span>Updated: {formatRelativeTime(setting.updated_at)}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2 w-full sm:w-auto">
          <div className="flex items-center gap-3 w-full sm:w-auto">
            {type === 'boolean' ? (
              <button
                onClick={() => handleBooleanToggle(key, currentValue)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
                  currentValue ? 'bg-[#D4D4D4]' : 'bg-[var(--color-surface-hover)] border border-[var(--color-border)]'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    currentValue ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            ) : (
              <div className="flex flex-col gap-1 flex-1 sm:flex-none">
                <div className="flex items-center gap-2">
                  <Input
                    type={type === 'password' && !showSecrets[key] ? 'password' : 'text'}
                    value={String(currentValue ?? '')}
                    onChange={(e) => handleInputChange(key, e.target.value, type)}
                    className={`w-full sm:w-64 ${validationError ? 'border-red-500' : ''}`}
                    rightIcon={type === 'password' ? (
                      <button type="button" onClick={() => toggleSecret(key)} className="text-[var(--color-text-muted)]">
                        {showSecrets[key] ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    ) : undefined}
                  />
                  {hasChanged && !validationError && (
                    <Button 
                      size="sm" 
                      onClick={() => handleUpdate(key)}
                      isLoading={updateSettingMutation.isPending && updateSettingMutation.variables?.key === key}
                    >
                      <Save size={14} />
                    </Button>
                  )}
                </div>
                {validationError && (
                  <div className="flex items-center gap-1 text-xs text-red-500">
                    <AlertCircle size={12} />
                    <span>{validationError}</span>
                  </div>
                )}
              </div>
            )}
          </div>
          {hasResetOption && isModified && (
            <button
              onClick={() => handleResetToDefault(key)}
              className="flex items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors"
              title="Reset to default value"
            >
              <RotateCcw size={12} />
              <span>Reset to Default</span>
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={settingsLoading} message="Loading system settings..." />
      
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">System Settings</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Dynamic application configuration and service monitoring.
        </p>
      </div>

      {/* Service & Stats Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Service Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {services.map((service) => (
                <div key={service.name} className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${
                      service.status === 'healthy' ? 'bg-green-500/10' : 'bg-red-500/10'
                    }`}>
                      <Server size={16} className={service.status === 'healthy' ? 'text-green-500' : 'text-red-500'} />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-[var(--color-text-primary)]">{service.name}</p>
                      <p className="text-xs text-[var(--color-text-muted)]">{service.uptime || '99.9% uptime'}</p>
                    </div>
                  </div>
                  <Badge variant={service.status === 'healthy' ? 'success' : 'error'} size="sm">
                    {service.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Usage Overview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Total Users</span>
              <span className="font-bold text-[var(--color-text-primary)]">{systemStats?.users?.total || 0}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[var(--color-border-light)]">
              <span className="text-sm text-[var(--color-text-secondary)]">Active Now</span>
              <span className="font-bold text-green-500">{systemStats?.users?.active || 0}</span>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-sm text-[var(--color-text-secondary)]">Database Type</span>
              <Badge variant="default" size="sm">PostgreSQL</Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search Input */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" size={18} />
        <Input
          type="text"
          placeholder="Search settings by key or description..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 w-full"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
          >
            ×
          </button>
        )}
      </div>

      {/* Configuration Tabs with Icons and Descriptions */}
      <div className="flex flex-wrap gap-3">
        {(['general', 'auth', 'email'] as const).map((tab) => {
          const meta = CATEGORY_META[tab];
          const Icon = meta.icon;
          const matchCount = getCategoryMatchCount(tab);
          const isActive = activeTab === tab;
          
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex items-start gap-3 p-4 rounded-xl border transition-all text-left min-w-[180px] ${
                isActive 
                  ? 'bg-white shadow-sm border-[var(--color-border)] ring-2 ring-blue-500/20' 
                  : 'bg-[var(--color-surface-hover)] border-transparent hover:border-[var(--color-border)]'
              }`}
            >
              <div className={`p-2 rounded-lg ${isActive ? 'bg-blue-500/10' : 'bg-[var(--color-surface)]'}`}>
                <Icon size={18} className={isActive ? 'text-blue-500' : 'text-[var(--color-text-muted)]'} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-medium ${isActive ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-text-muted)]'}`}>
                    {meta.label}
                  </span>
                  {searchQuery && matchCount > 0 && (
                    <Badge variant="default" size="sm">{matchCount}</Badge>
                  )}
                </div>
                <p className="text-xs text-[var(--color-text-muted)] mt-0.5 line-clamp-2">
                  {meta.description}
                </p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <Card>
        <CardContent className="divide-y divide-[var(--color-border-light)]">
          {/* Empty state when no settings are loaded */}
          {!settingsLoading && settings.length === 0 && (
            <div className="py-12 text-center">
              <AlertCircle size={32} className="mx-auto text-[var(--color-text-muted)] mb-3" />
              <p className="text-sm font-medium text-[var(--color-text-primary)]">
                No settings configured
              </p>
              <p className="text-xs text-[var(--color-text-muted)] mt-1">
                Settings will appear here once they are initialized in the database.
              </p>
            </div>
          )}
          {/* Loading skeleton */}
          {settingsLoading && (
            <div className="py-8 space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="animate-pulse flex items-center justify-between py-4">
                  <div className="flex-1">
                    <div className="h-4 bg-[var(--color-surface-hover)] rounded w-1/3 mb-2"></div>
                    <div className="h-3 bg-[var(--color-surface-hover)] rounded w-1/2"></div>
                  </div>
                  <div className="h-8 bg-[var(--color-surface-hover)] rounded w-64"></div>
                </div>
              ))}
            </div>
          )}
          {/* Render settings only when loaded */}
          {!settingsLoading && settings.length > 0 && (
            <>
              {activeTab === 'general' && (
                <>
                  {renderSettingRow('site.name')}
                  {renderSettingRow('site.logo_url')}
                </>
              )}
              {activeTab === 'auth' && (
                <>
                  {renderSettingRow('auth.allow_registration', 'boolean')}
                  {renderSettingRow('auth.require_email_verification', 'boolean')}
                  {renderSettingRow('auth.mfa_enabled', 'boolean')}
                </>
              )}
              {activeTab === 'email' && (
                <>
                  {renderSettingRow('email.provider')}
                  {renderSettingRow('email.from_name')}
                  {renderSettingRow('email.from_email')}
                  <div className="py-6 mt-4 bg-[var(--color-surface-hover)]/30 rounded-xl px-4">
                    <h3 className="text-sm font-semibold text-[var(--color-text-primary)] mb-4 flex items-center gap-2">
                      <RefreshCw size={16} /> SMTP Configuration
                    </h3>
                    <div className="space-y-2">
                      {renderSettingRow('email.smtp_host')}
                      {renderSettingRow('email.smtp_port', 'number')}
                      {renderSettingRow('email.smtp_user')}
                      {renderSettingRow('email.smtp_password', 'password')}
                    </div>
                  </div>
                </>
              )}
              {/* Empty state when search has no results in current tab */}
              {searchQuery && getCategoryMatchCount(activeTab) === 0 && (
                <div className="py-12 text-center">
                  <Search size={32} className="mx-auto text-[var(--color-text-muted)] mb-3" />
                  <p className="text-sm text-[var(--color-text-muted)]">
                    No settings found matching "{searchQuery}" in this category.
                  </p>
                  <p className="text-xs text-[var(--color-text-muted)] mt-1">
                    Try a different search term or check other categories.
                  </p>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Save All Changes Button */}
      {pendingChanges.length > 0 && (
        <div className="flex items-center justify-between p-4 rounded-xl bg-amber-500/5 border border-amber-500/20">
          <div className="flex items-center gap-3">
            <Save size={20} className="text-amber-500" />
            <div>
              <p className="text-sm font-medium text-[var(--color-text-primary)]">
                {pendingChanges.length} unsaved change{pendingChanges.length !== 1 ? 's' : ''}
              </p>
              <p className="text-xs text-[var(--color-text-muted)]">
                Click save to apply all pending changes at once
              </p>
            </div>
          </div>
          <Button onClick={handleSaveAllChanges} disabled={updateSettingMutation.isPending}>
            <Save size={16} className="mr-2" />
            Save All Changes
          </Button>
        </div>
      )}

      {/* Bottom Info */}
      <div className="flex items-center gap-3 p-4 rounded-xl bg-blue-500/5 border border-blue-500/10">
        <Shield size={20} className="text-blue-500" />
        <p className="text-xs text-[var(--color-text-secondary)]">
          Some infrastructure settings (like Database URLs and JWT Secrets) are managed via environment variables for security reasons and cannot be modified from the UI.
        </p>
      </div>

      {/* Security Setting Confirmation Dialog */}
      <ConfirmDialog
        isOpen={confirmDialog.isOpen}
        onClose={() => setConfirmDialog(prev => ({ ...prev, isOpen: false }))}
        onConfirm={handleConfirmSecurityChange}
        title={confirmDialog.title}
        message={confirmDialog.message}
        confirmText="Yes, Change Setting"
        cancelText="Cancel"
        variant="warning"
        loading={updateSettingMutation.isPending}
      />
    </div>
  );
}
import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  Shield,
  Save,
  RefreshCw,
  Eye,
  EyeOff,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, Button, Input, LoadingBar } from '../../components/ui';
import { adminService } from '../../api/services';
import { useToast } from '../../components/ui/Toast';

export function AdminSettingsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'general' | 'auth' | 'email'>('general');
  const [localSettings, setLocalSettings] = useState<Record<string, any>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});

  // Fetch settings
  const { data: settingsData = [], isLoading: settingsLoading } = useQuery({
    queryKey: ['admin-settings'],
    queryFn: () => adminService.listSettings(),
  });

  const settings = Array.isArray(settingsData) ? settingsData : [];

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

  useEffect(() => {
    if (settings && settings.length > 0) {
      const initialSettings: Record<string, any> = {};
      settings.forEach(s => {
        if (s && s.key) {
          initialSettings[s.key] = s.value;
        }
      });
      setLocalSettings(prev => ({ ...initialSettings, ...prev }));
    }
  }, [settings]);

  // Update setting mutation
  const updateSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: any }) => adminService.updateSetting(key, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-settings'] });
      showToast({ title: 'Success', message: 'Setting updated successfully', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update setting', type: 'error' });
    },
  });

  const handleUpdate = (key: string) => {
    if (localSettings[key] !== undefined) {
      updateSettingMutation.mutate({ key, value: localSettings[key] });
    }
  };

  const handleInputChange = (key: string, value: any) => {
    setLocalSettings(prev => ({ ...prev, [key]: value }));
  };

  const toggleSecret = (key: string) => {
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const renderSettingRow = (key: string, type: 'text' | 'number' | 'boolean' | 'password' = 'text') => {
    if (!Array.isArray(settings)) return null;
    const setting = settings.find(s => s.key === key);
    if (!setting) return null;

    const currentValue = localSettings[key] !== undefined ? localSettings[key] : setting.value;
    const hasChanged = currentValue !== setting.value;

    return (
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 py-4 border-b border-[var(--color-border-light)] last:border-0">
        <div className="flex-1">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">{setting.key}</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">{setting.description}</p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          {type === 'boolean' ? (
            <button
              onClick={() => {
                const newValue = !currentValue;
                handleInputChange(key, newValue);
                updateSettingMutation.mutate({ key, value: newValue });
              }}
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
            <div className="flex items-center gap-2 flex-1 sm:flex-none">
              <Input
                type={type === 'password' && !showSecrets[key] ? 'password' : 'text'}
                value={currentValue ?? ''}
                onChange={(e) => handleInputChange(key, type === 'number' ? parseInt(e.target.value) || 0 : e.target.value)}
                className="w-full sm:w-64"
                rightIcon={type === 'password' ? (
                  <button type="button" onClick={() => toggleSecret(key)} className="text-[var(--color-text-muted)]">
                    {showSecrets[key] ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                ) : undefined}
              />
              {hasChanged && (
                <Button 
                  size="sm" 
                  onClick={() => handleUpdate(key)}
                  isLoading={updateSettingMutation.isPending && updateSettingMutation.variables?.key === key}
                >
                  <Save size={14} />
                </Button>
              )}
            </div>
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

      {/* Configuration Tabs */}
      <div className="flex gap-2 p-1 bg-[var(--color-surface-hover)] rounded-xl w-fit">
        <button
          onClick={() => setActiveTab('general')}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
            activeTab === 'general' ? 'bg-white shadow-sm text-[var(--color-text-primary)]' : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
          }`}
        >
          General
        </button>
        <button
          onClick={() => setActiveTab('auth')}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
            activeTab === 'auth' ? 'bg-white shadow-sm text-[var(--color-text-primary)]' : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
          }`}
        >
          Authentication
        </button>
        <button
          onClick={() => setActiveTab('email')}
          className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
            activeTab === 'email' ? 'bg-white shadow-sm text-[var(--color-text-primary)]' : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]'
          }`}
        >
          Email (SMTP)
        </button>
      </div>

      {/* Tab Content */}
      <Card>
        <CardContent className="divide-y divide-[var(--color-border-light)]">
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
        </CardContent>
      </Card>

      {/* Bottom Info */}
      <div className="flex items-center gap-3 p-4 rounded-xl bg-blue-500/5 border border-blue-500/10">
        <Shield size={20} className="text-blue-500" />
        <p className="text-xs text-[var(--color-text-secondary)]">
          Some infrastructure settings (like Database URLs and JWT Secrets) are managed via environment variables for security reasons and cannot be modified from the UI.
        </p>
      </div>
    </div>
  );
}
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { usePreferences, useUpdatePreferences } from '../../hooks/usePreferences';
import { useToast } from '../ui/Toast';
import { Bell, Mail, Shield, Megaphone, Newspaper, Loader2 } from 'lucide-react';
import { Select } from '../ui/Select';
import { Skeleton } from '../ui/LoadingSkeleton';
import type { UpdatePreferencesRequest } from '../../types';

interface ToggleSwitchProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
}

function ToggleSwitch({ enabled, onChange, disabled }: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      disabled={disabled}
      onClick={() => onChange(!enabled)}
      className={`
        relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full
        border-2 border-transparent transition-colors duration-200 ease-in-out
        focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:ring-offset-2
        ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
        ${enabled ? 'bg-[var(--color-primary)]' : 'bg-[var(--color-border)]'}
      `}
    >
      <span
        className={`
          pointer-events-none inline-block h-5 w-5 transform rounded-full
          bg-white shadow ring-0 transition duration-200 ease-in-out
          ${enabled ? 'translate-x-5' : 'translate-x-0'}
        `}
      />
    </button>
  );
}

interface NotificationSettingRowProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  isUpdating?: boolean;
}

function NotificationSettingRow({
  icon,
  title,
  description,
  enabled,
  onChange,
  isUpdating,
}: NotificationSettingRowProps) {
  return (
    <div className="flex items-start justify-between gap-4 py-4 border-b border-[var(--color-border)] last:border-b-0">
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-[var(--color-primary-dark)] text-[var(--color-text-secondary)] flex-shrink-0">
          {icon}
        </div>
        <div>
          <h4 className="text-sm font-medium text-[var(--color-text-primary)]">{title}</h4>
          <p className="text-sm text-[var(--color-text-muted)] mt-0.5">{description}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        {isUpdating && <Loader2 size={16} className="animate-spin text-[var(--color-text-muted)]" />}
        <ToggleSwitch enabled={enabled} onChange={onChange} disabled={isUpdating} />
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="space-y-4">
      {[1, 2, 3, 4, 5].map((i) => (
        <div key={i} className="flex items-center justify-between py-4 border-b border-[var(--color-border)] last:border-b-0">
          <div className="flex items-center gap-3">
            <Skeleton variant="rectangular" width="40px" height="40px" />
            <div className="space-y-2">
              <Skeleton width="150px" height="16px" />
              <Skeleton width="250px" height="14px" />
            </div>
          </div>
          <Skeleton width="44px" height="24px" />
        </div>
      ))}
    </div>
  );
}

export function NotificationPreferencesCard() {
  const { data: preferences, isLoading, error } = usePreferences();
  const updatePreferences = useUpdatePreferences();
  const { showToast } = useToast();

  const handleUpdate = async (key: keyof UpdatePreferencesRequest, value: boolean | string) => {
    try {
      await updatePreferences.mutateAsync({ [key]: value });
      showToast({
        type: 'success',
        title: 'Preferences updated',
        message: 'Your notification preferences have been saved.',
      });
    } catch (err) {
      showToast({
        type: 'error',
        title: 'Update failed',
        message: err instanceof Error ? err.message : 'Failed to update preferences.',
      });
    }
  };

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Notification Preferences</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <p className="text-[var(--color-error)]">Failed to load preferences</p>
            <p className="text-sm text-[var(--color-text-muted)] mt-1">
              {error instanceof Error ? error.message : 'Please try again later.'}
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const digestOptions = [
    { value: 'none', label: 'None' },
    { value: 'daily', label: 'Daily' },
    { value: 'weekly', label: 'Weekly' },
    { value: 'monthly', label: 'Monthly' },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Notification Preferences</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingState />
        ) : (
          <div>
            <NotificationSettingRow
              icon={<Shield size={20} />}
              title="Security alerts"
              description="Get notified about security events like new logins and password changes"
              enabled={preferences?.email_security_alerts ?? false}
              onChange={(enabled) => handleUpdate('email_security_alerts', enabled)}
              isUpdating={updatePreferences.isPending}
            />

            <NotificationSettingRow
              icon={<Megaphone size={20} />}
              title="Product updates"
              description="Receive updates about new features and improvements"
              enabled={preferences?.email_product_updates ?? false}
              onChange={(enabled) => handleUpdate('email_product_updates', enabled)}
              isUpdating={updatePreferences.isPending}
            />

            <NotificationSettingRow
              icon={<Newspaper size={20} />}
              title="Marketing emails"
              description="Occasional tips and promotional content"
              enabled={preferences?.email_marketing ?? false}
              onChange={(enabled) => handleUpdate('email_marketing', enabled)}
              isUpdating={updatePreferences.isPending}
            />

            <NotificationSettingRow
              icon={<Bell size={20} />}
              title="Push notifications"
              description="Enable browser push notifications"
              enabled={preferences?.push_enabled ?? false}
              onChange={(enabled) => handleUpdate('push_enabled', enabled)}
              isUpdating={updatePreferences.isPending}
            />

            <div className="flex items-start justify-between gap-4 py-4">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-[var(--color-primary-dark)] text-[var(--color-text-secondary)] flex-shrink-0">
                  <Mail size={20} />
                </div>
                <div>
                  <h4 className="text-sm font-medium text-[var(--color-text-primary)]">
                    Email digest frequency
                  </h4>
                  <p className="text-sm text-[var(--color-text-muted)] mt-0.5">
                    How often you want to receive email digests
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {updatePreferences.isPending && (
                  <Loader2 size={16} className="animate-spin text-[var(--color-text-muted)]" />
                )}
                <Select
                  options={digestOptions}
                  value={preferences?.email_digest_frequency ?? 'none'}
                  onChange={(e) => handleUpdate('email_digest_frequency', e.target.value)}
                  disabled={updatePreferences.isPending}
                  className="w-32"
                />
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

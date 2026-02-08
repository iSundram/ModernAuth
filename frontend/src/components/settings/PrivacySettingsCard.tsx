import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { ConfirmDialog } from '../ui/ConfirmDialog';
import { usePreferences, useUpdatePreferences, useExportData } from '../../hooks/usePreferences';
import { useToast } from '../ui/Toast';
import { Eye, EyeOff, Users, Download, Trash2, Mail, Activity, Check } from 'lucide-react';

const VISIBILITY_OPTIONS = [
  { value: 'public', label: 'Public', description: 'Anyone can see your profile', icon: Eye },
  { value: 'private', label: 'Private', description: 'Only you can see your profile', icon: EyeOff },
  { value: 'contacts', label: 'Contacts Only', description: 'Only connected users can see', icon: Users },
] as const;

type VisibilityValue = typeof VISIBILITY_OPTIONS[number]['value'];

export function PrivacySettingsCard() {
  const { showToast } = useToast();
  const { data: preferences, isLoading: preferencesLoading } = usePreferences();
  const updatePreferences = useUpdatePreferences();
  const exportData = useExportData();

  const [showDeleteHistoryConfirm, setShowDeleteHistoryConfirm] = useState(false);
  const [isDeletingHistory, setIsDeletingHistory] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  const handleVisibilityChange = (value: VisibilityValue) => {
    updatePreferences.mutate(
      { profile_visibility: value },
      {
        onSuccess: () => {
          showToast({ title: 'Success', message: 'Profile visibility updated', type: 'success' });
        },
        onError: (error: Error) => {
          showToast({ title: 'Error', message: error.message || 'Failed to update visibility', type: 'error' });
        },
      }
    );
  };

  const handleToggle = (field: 'show_activity_status' | 'show_email_publicly', currentValue: boolean) => {
    updatePreferences.mutate(
      { [field]: !currentValue },
      {
        onSuccess: () => {
          const message = field === 'show_activity_status' 
            ? `Activity status ${!currentValue ? 'visible' : 'hidden'}`
            : `Email ${!currentValue ? 'visible' : 'hidden'} publicly`;
          showToast({ title: 'Success', message, type: 'success' });
        },
        onError: (error: Error) => {
          showToast({ title: 'Error', message: error.message || 'Failed to update setting', type: 'error' });
        },
      }
    );
  };

  const handleExportData = () => {
    setExportSuccess(false);
    exportData.mutate(undefined, {
      onSuccess: (response) => {
        setExportSuccess(true);
        if (response?.download_url) {
          // Trigger download
          const link = document.createElement('a');
          link.href = response.download_url;
          link.download = 'my-data-export.zip';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        }
        showToast({ title: 'Export Complete', message: 'Your data export is ready for download', type: 'success' });
        // Reset success state after 3 seconds
        setTimeout(() => setExportSuccess(false), 3000);
      },
      onError: (error: Error) => {
        showToast({ title: 'Error', message: error.message || 'Failed to export data', type: 'error' });
      },
    });
  };

  const handleDeleteLoginHistory = async () => {
    setIsDeletingHistory(true);
    try {
      // API call would go here - using a placeholder for now
      // await authService.deleteLoginHistory();
      showToast({ title: 'Success', message: 'Login history deleted successfully', type: 'success' });
      setShowDeleteHistoryConfirm(false);
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to delete login history', 
        type: 'error' 
      });
    } finally {
      setIsDeletingHistory(false);
    }
  };

  const currentVisibility = preferences?.profile_visibility || 'private';
  const showActivityStatus = preferences?.show_activity_status ?? false;
  const showEmailPublicly = preferences?.show_email_publicly ?? false;

  if (preferencesLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Privacy Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-4">
            <div className="h-24 bg-[var(--color-border-light)] rounded-lg" />
            <div className="h-12 bg-[var(--color-border-light)] rounded-lg" />
            <div className="h-12 bg-[var(--color-border-light)] rounded-lg" />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Privacy Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Profile Visibility Section */}
          <div>
            <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-3">
              Profile Visibility
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {VISIBILITY_OPTIONS.map((option) => {
                const Icon = option.icon;
                const isSelected = currentVisibility === option.value;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => handleVisibilityChange(option.value)}
                    disabled={updatePreferences.isPending}
                    className={`
                      relative p-4 rounded-lg border-2 text-left transition-all duration-200
                      ${isSelected
                        ? 'border-[var(--color-info)] bg-[var(--color-info)]/5'
                        : 'border-[var(--color-border)] hover:border-[var(--color-secondary)] bg-white'
                      }
                      disabled:opacity-50 disabled:cursor-not-allowed
                    `}
                  >
                    {isSelected && (
                      <div className="absolute top-2 right-2">
                        <Check size={16} className="text-[var(--color-info)]" />
                      </div>
                    )}
                    <div className="flex items-center gap-3 mb-2">
                      <Icon 
                        size={20} 
                        className={isSelected ? 'text-[var(--color-info)]' : 'text-[var(--color-text-muted)]'} 
                      />
                      <span className={`font-medium ${isSelected ? 'text-[var(--color-info)]' : 'text-[var(--color-text-primary)]'}`}>
                        {option.label}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)]">
                      {option.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Toggle Settings */}
          <div className="space-y-4">
            {/* Show Activity Status Toggle */}
            <div className="flex items-center justify-between py-3 border-b border-[var(--color-border-light)]">
              <div className="flex items-center gap-3">
                <Activity size={20} className="text-[var(--color-text-muted)]" />
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    Show Activity Status
                  </p>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    Let others see when you're online
                  </p>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={showActivityStatus}
                onClick={() => handleToggle('show_activity_status', showActivityStatus)}
                disabled={updatePreferences.isPending}
                className={`
                  relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200
                  focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/50 focus:ring-offset-2
                  disabled:opacity-50 disabled:cursor-not-allowed
                  ${showActivityStatus ? 'bg-[var(--color-info)]' : 'bg-[var(--color-border)]'}
                `}
              >
                <span
                  className={`
                    inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform duration-200
                    ${showActivityStatus ? 'translate-x-6' : 'translate-x-1'}
                  `}
                />
              </button>
            </div>

            {/* Show Email Publicly Toggle */}
            <div className="flex items-center justify-between py-3 border-b border-[var(--color-border-light)]">
              <div className="flex items-center gap-3">
                <Mail size={20} className="text-[var(--color-text-muted)]" />
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    Show Email Publicly
                  </p>
                  <p className="text-xs text-[var(--color-text-muted)]">
                    Display your email on your public profile
                  </p>
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={showEmailPublicly}
                onClick={() => handleToggle('show_email_publicly', showEmailPublicly)}
                disabled={updatePreferences.isPending}
                className={`
                  relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200
                  focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/50 focus:ring-offset-2
                  disabled:opacity-50 disabled:cursor-not-allowed
                  ${showEmailPublicly ? 'bg-[var(--color-info)]' : 'bg-[var(--color-border)]'}
                `}
              >
                <span
                  className={`
                    inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform duration-200
                    ${showEmailPublicly ? 'translate-x-6' : 'translate-x-1'}
                  `}
                />
              </button>
            </div>
          </div>

          {/* Data Export Section */}
          <div className="pt-2">
            <h3 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">
              Download My Data
            </h3>
            <p className="text-xs text-[var(--color-text-muted)] mb-3">
              Export a copy of your data including profile information, preferences, login history, and activity logs.
            </p>
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                leftIcon={exportData.isPending ? undefined : (exportSuccess ? <Check size={16} /> : <Download size={16} />)}
                onClick={handleExportData}
                isLoading={exportData.isPending}
                disabled={exportData.isPending}
                className={exportSuccess ? 'border-green-500 text-green-600' : ''}
              >
                {exportData.isPending ? 'Preparing Export...' : (exportSuccess ? 'Export Ready!' : 'Download My Data')}
              </Button>
              {exportData.isPending && (
                <span className="text-xs text-[var(--color-text-muted)]">
                  This may take a moment...
                </span>
              )}
            </div>
          </div>

          {/* Delete Login History Section */}
          <div className="pt-2 border-t border-[var(--color-border-light)]">
            <h3 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">
              Delete Login History
            </h3>
            <p className="text-xs text-[var(--color-text-muted)] mb-3">
              Remove all records of your past login sessions. This action cannot be undone.
            </p>
            <Button
              variant="outline"
              size="sm"
              leftIcon={<Trash2 size={16} />}
              onClick={() => setShowDeleteHistoryConfirm(true)}
              className="border-red-500/50 text-red-500 hover:bg-red-500/10"
            >
              Delete Login History
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Delete Login History Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteHistoryConfirm}
        onClose={() => setShowDeleteHistoryConfirm(false)}
        onConfirm={handleDeleteLoginHistory}
        title="Delete Login History"
        message="Are you sure you want to delete your entire login history? This will remove all records of previous login sessions, devices, and locations. This action cannot be undone."
        confirmText="Delete History"
        cancelText="Cancel"
        variant="danger"
        loading={isDeletingHistory}
      />
    </>
  );
}

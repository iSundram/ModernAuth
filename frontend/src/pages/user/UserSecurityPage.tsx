import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import QRCode from "react-qr-code";
import { 
  Smartphone, Key, CheckCircle, AlertCircle, LogOut, 
  Monitor, Trash2, Lock, Eye, EyeOff, MapPin, Clock, Globe, Fingerprint, Mail
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Input, LoadingBar, Badge, ConfirmDialog, Modal } from '../../components/ui';
import { useToast } from '../../components/ui/Toast';
import { deviceService, sessionService, authService } from '../../api/services';
import { 
  PasskeySetup, 
  PasskeyList, 
  EmailMFASetup, 
  MFAStatusOverview,
  MFAPreferencesSelector,
  PasswordStrength 
} from '../../components/security';
import type { UserDevice, Session } from '../../types';

export function UserSecurityPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [isSettingUpMfa, setIsSettingUpMfa] = useState(false);
  const [mfaData, setMfaData] = useState<{ secret: string; url: string } | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [isMfaEnabled, setIsMfaEnabled] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [backupCodeCount, setBackupCodeCount] = useState<number | null>(null);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [disableMfaCode, setDisableMfaCode] = useState('');
  const [showDisableMfa, setShowDisableMfa] = useState(false);
  
  // Password change state
  const [showPasswordChange, setShowPasswordChange] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });

  // Confirmation dialogs
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const [confirmRemoveDevice, setConfirmRemoveDevice] = useState<UserDevice | null>(null);

  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch devices
  const { data: devices = [], isLoading: devicesLoading } = useQuery({
    queryKey: ['devices'],
    queryFn: () => deviceService.list(),
  });

  // Fetch active sessions
  const { data: activeSessions = [], isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => sessionService.list({ limit: 50 }),
  });

  // Fetch login history
  const { data: loginHistory = [], isLoading: historyLoading } = useQuery({
    queryKey: ['login-history'],
    queryFn: () => deviceService.getLoginHistory({ limit: 20 }),
  });

  // Fetch MFA status
  const { data: mfaStatus, refetch: refetchMfaStatus } = useQuery({
    queryKey: ['mfa-status'],
    queryFn: () => authService.getMfaStatus(),
    retry: false,
  });

  // Fetch backup code count - this also tells us if MFA is enabled
  const { data: backupCodeCountData, refetch: refetchBackupCount, error: backupCodeError } = useQuery({
    queryKey: ['backup-code-count'],
    queryFn: () => authService.getBackupCodeCount(),
    retry: false, // Don't retry if MFA is not enabled
  });

  useEffect(() => {
    if (backupCodeCountData) {
      setBackupCodeCount(backupCodeCountData.remaining_codes);
    } else if (backupCodeError) {
      setBackupCodeCount(null);
    }
  }, [backupCodeCountData, backupCodeError]);

  // Check if TOTP (Authenticator App) is specifically enabled
  useEffect(() => {
    if (mfaStatus) {
      // Only show "MFA Enabled" for TOTP (Authenticator App) in this section
      // Email MFA is shown separately in MFAStatusOverview
      setIsMfaEnabled(mfaStatus.totp_enabled);
    }
  }, [mfaStatus]);

  // Revoke all sessions mutation
  const revokeAllSessionsMutation = useMutation({
    mutationFn: () => sessionService.revokeAll(),
    onSuccess: () => {
      showToast({ title: 'Success', message: 'All sessions have been revoked', type: 'success' });
      setConfirmRevokeAll(false);
      // Force logout after a delay
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to revoke sessions', type: 'error' });
    },
  });

  // Revoke single session mutation
  const revokeSessionMutation = useMutation({
    mutationFn: (sessionId: string) => sessionService.revoke(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] });
      showToast({ title: 'Success', message: 'Session revoked', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to revoke session', type: 'error' });
    },
  });


  // Trust device mutation
  const trustDeviceMutation = useMutation({
    mutationFn: (deviceId: string) => deviceService.trust(deviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      showToast({ title: 'Success', message: 'Device trusted successfully', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to trust device', type: 'error' });
    },
  });

  // Untrust device mutation
  const untrustDeviceMutation = useMutation({
    mutationFn: (deviceId: string) => deviceService.untrust(deviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      showToast({ title: 'Success', message: 'Device untrusted', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to untrust device', type: 'error' });
    },
  });

  // Remove device mutation
  const removeDeviceMutation = useMutation({
    mutationFn: (deviceId: string) => deviceService.remove(deviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      showToast({ title: 'Success', message: 'Device removed successfully', type: 'success' });
      setConfirmRemoveDevice(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to remove device', type: 'error' });
    },
  });

  // Revoke MFA trust mutation (removes "remember this device for MFA" trust)
  const revokeMfaTrustMutation = useMutation({
    mutationFn: (deviceFingerprint: string) => authService.revokeMfaTrust(deviceFingerprint),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      showToast({ 
        title: 'Success', 
        message: 'MFA trust revoked. This device will require MFA on next login.', 
        type: 'success' 
      });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to revoke MFA trust', type: 'error' });
    },
  });

  const handleStartMfaSetup = async () => {
    setIsLoading(true);
    try {
      const data = await authService.setupMfa();
      setMfaData(data);
      setIsSettingUpMfa(true);
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to start MFA setup', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleEnableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verificationCode || verificationCode.length !== 6) {
      showToast({ title: 'Error', message: 'Please enter a valid 6-digit code', type: 'error' });
      return;
    }

    setIsLoading(true);
    try {
      await authService.enableMfa({ code: verificationCode });
      setIsMfaEnabled(true);
      setIsSettingUpMfa(false);
      setMfaData(null);
      setVerificationCode('');
      showToast({ title: 'Success', message: 'MFA has been enabled successfully', type: 'success' });
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to verify code', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Generate backup codes mutation
  const generateBackupCodesMutation = useMutation({
    mutationFn: () => authService.generateBackupCodes(),
    onSuccess: (response) => {
      setBackupCodes(response.backup_codes);
      setShowBackupCodes(true);
      refetchBackupCount();
      showToast({ title: 'Success', message: 'Backup codes generated. Save them now!', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to generate backup codes', type: 'error' });
    },
  });

  // Disable MFA mutation
  const disableMfaMutation = useMutation({
    mutationFn: (code: string) => authService.disableMfa({ code }),
    onSuccess: () => {
      setIsMfaEnabled(false);
      setShowDisableMfa(false);
      setDisableMfaCode('');
      refetchBackupCount();
      showToast({ title: 'Success', message: 'MFA has been disabled', type: 'success' });
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to disable MFA', type: 'error' });
    },
  });

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!disableMfaCode || disableMfaCode.length !== 6) {
      showToast({ title: 'Error', message: 'Please enter a valid 6-digit code', type: 'error' });
      return;
    }
    disableMfaMutation.mutate(disableMfaCode);
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      showToast({ title: 'Error', message: 'Passwords do not match', type: 'error' });
      return;
    }

    if (passwordData.newPassword.length < 8) {
      showToast({ title: 'Error', message: 'Password must be at least 8 characters', type: 'error' });
      return;
    }

    setIsLoading(true);
    try {
      await authService.changePassword({
        current_password: passwordData.currentPassword,
        new_password: passwordData.newPassword,
      });
      showToast({ title: 'Success', message: 'Password changed successfully', type: 'success' });
      setShowPasswordChange(false);
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to change password', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading || devicesLoading || historyLoading || sessionsLoading} message="Loading..." />
      
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Security Settings</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Manage your account security, devices, and active sessions.
        </p>
      </div>

      {/* MFA Status Overview */}
      <MFAStatusOverview />

      {/* MFA Preferences - show only if multiple methods enabled */}
      {mfaStatus && (
        (mfaStatus.totp_enabled ? 1 : 0) + 
        (mfaStatus.email_enabled ? 1 : 0) + 
        (mfaStatus.webauthn_enabled ? 1 : 0)
      ) >= 2 && (
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-[var(--color-text-primary)]">Preferred MFA Method</p>
                <p className="text-sm text-[var(--color-text-secondary)]">
                  Choose which method to use by default when signing in
                </p>
              </div>
              <MFAPreferencesSelector
                currentPreferred={mfaStatus?.preferred_method || null}
                enabledMethods={{
                  totp: mfaStatus?.totp_enabled || false,
                  email: mfaStatus?.email_enabled || false,
                  webauthn: mfaStatus?.webauthn_enabled || false,
                }}
                onSuccess={() => refetchMfaStatus()}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* MFA Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
              <Smartphone size={20} className="text-[#D4D4D4]" />
            </div>
            <CardTitle>Authenticator App</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {isMfaEnabled ? (
            <div className="flex flex-col items-center justify-center py-6 text-center">
              <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mb-4">
                <CheckCircle size={32} className="text-green-500" />
              </div>
              <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Authenticator Enabled</h3>
              <p className="text-[var(--color-text-secondary)] mt-2 mb-4">
                Your account is secured with an authenticator app (TOTP).
              </p>
              {backupCodeCount !== null && (
                <p className="text-sm text-[var(--color-text-secondary)] mb-4">
                  Remaining backup codes: <span className="font-medium">{backupCodeCount}</span>
                </p>
              )}
              <div className="flex gap-3">
                <Button 
                  variant="outline" 
                  onClick={() => setShowDisableMfa(true)}
                  className="flex-1"
                >
                  Disable Authenticator
                </Button>
                <Button 
                  variant="outline" 
                  onClick={() => generateBackupCodesMutation.mutate()}
                  disabled={generateBackupCodesMutation.isPending}
                  className="flex-1"
                >
                  Generate Backup Codes
                </Button>
              </div>
            </div>
          ) : !isSettingUpMfa ? (
            <div className="space-y-4">
              <p className="text-[var(--color-text-secondary)]">
                Add an extra layer of security by setting up an authenticator app like Google Authenticator or Authy.
              </p>
              
              <div className="flex items-start gap-3 p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                <Smartphone className="mt-1 text-[var(--color-text-muted)]" size={20} />
                <div>
                  <p className="font-medium text-[var(--color-text-primary)]">How it works</p>
                  <p className="text-sm text-[var(--color-text-secondary)]">
                    Scan a QR code with your authenticator app to generate time-based verification codes.
                  </p>
                </div>
              </div>

              <Button onClick={handleStartMfaSetup} className="w-full">
                Setup Authenticator
              </Button>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <div className="flex gap-3">
                  <AlertCircle className="text-blue-500 shrink-0" size={20} />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-[var(--color-text-primary)]">
                      Scan the QR Code
                    </p>
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      Open your authenticator app and scan the code or manually enter the secret key below.
                    </p>
                  </div>
                </div>
              </div>

              {mfaData?.url && (
                <div className="flex justify-center p-4 bg-white rounded-lg border border-[var(--color-border)]">
                  <QRCode value={mfaData.url} size={200} />
                </div>
              )}

              <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] space-y-2">
                <p className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                  Manual Entry Secret Key
                </p>
                <div className="flex items-center gap-2 font-mono text-sm break-all">
                  <Key size={14} className="text-[var(--color-text-muted)] shrink-0" />
                  {mfaData?.secret}
                </div>
              </div>

              <form onSubmit={handleEnableMfa} className="space-y-4">
                <Input
                  label="Verification Code"
                  placeholder="Enter 6-digit code"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength={6}
                  className="text-center tracking-widest text-lg"
                />
                
                <div className="flex gap-3">
                  <Button 
                    type="button" 
                    variant="ghost" 
                    onClick={() => {
                      setIsSettingUpMfa(false);
                      setMfaData(null);
                    }}
                    className="flex-1"
                  >
                    Cancel
                  </Button>
                  <Button 
                    type="submit" 
                    variant="primary"
                    className="flex-1"
                    isLoading={isLoading}
                    disabled={verificationCode.length !== 6}
                  >
                    Verify & Enable
                  </Button>
                </div>
              </form>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Passkeys Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
                <Fingerprint size={20} className="text-[#D4D4D4]" />
              </div>
              <div>
                <CardTitle>Passkeys</CardTitle>
                <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                  Use biometrics or security keys for passwordless login
                </p>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <PasskeyList />
          <PasskeySetup onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['webauthn-credentials'] });
            queryClient.invalidateQueries({ queryKey: ['mfa-status'] });
          }} />
        </CardContent>
      </Card>

      {/* Email MFA Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
              <Mail size={20} className="text-[#D4D4D4]" />
            </div>
            <CardTitle>Email Authentication</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <EmailMFASetup 
            isEnabled={mfaStatus?.email_enabled || false} 
            onSuccess={() => refetchMfaStatus()}
          />
        </CardContent>
      </Card>

      {/* Backup Codes Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
              <Key size={20} className="text-[#D4D4D4]" />
            </div>
            <div>
              <CardTitle>Backup Codes</CardTitle>
              <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                Emergency codes for account recovery
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {backupCodeCount !== null && backupCodeCount > 0 ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    backupCodeCount > 5 ? 'bg-green-500/10' : backupCodeCount > 2 ? 'bg-yellow-500/10' : 'bg-red-500/10'
                  }`}>
                    <span className={`text-lg font-bold ${
                      backupCodeCount > 5 ? 'text-green-500' : backupCodeCount > 2 ? 'text-yellow-500' : 'text-red-500'
                    }`}>
                      {backupCodeCount}
                    </span>
                  </div>
                  <div>
                    <p className="font-medium text-[var(--color-text-primary)]">
                      {backupCodeCount} backup code{backupCodeCount !== 1 ? 's' : ''} remaining
                    </p>
                    <p className="text-sm text-[var(--color-text-secondary)]">
                      {backupCodeCount <= 2 
                        ? 'Consider generating new codes soon' 
                        : 'Use these if you lose access to your MFA device'}
                    </p>
                  </div>
                </div>
              </div>
              
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => generateBackupCodesMutation.mutate()}
                disabled={generateBackupCodesMutation.isPending}
              >
                {generateBackupCodesMutation.isPending ? 'Generating...' : 'Generate New Backup Codes'}
              </Button>
              
              <p className="text-xs text-[var(--color-text-muted)] text-center">
                Generating new codes will invalidate all existing backup codes
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-3 p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                <AlertCircle size={20} className="text-yellow-500 shrink-0" />
                <div>
                  <p className="font-medium text-[var(--color-text-primary)]">No backup codes</p>
                  <p className="text-sm text-[var(--color-text-secondary)]">
                    Generate backup codes to ensure you can access your account if you lose your MFA device.
                  </p>
                </div>
              </div>
              
              <Button 
                variant="primary" 
                className="w-full"
                onClick={() => generateBackupCodesMutation.mutate()}
                disabled={generateBackupCodesMutation.isPending}
              >
                {generateBackupCodesMutation.isPending ? 'Generating...' : 'Generate Backup Codes'}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Password Management */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
                <Key size={20} className="text-[#D4D4D4]" />
              </div>
              <CardTitle>Password</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {!showPasswordChange ? (
              <div className="space-y-4">
                <p className="text-[var(--color-text-secondary)]">
                  Regularly updating your password helps keep your account secure.
                </p>
                <Button variant="outline" className="w-full" onClick={() => setShowPasswordChange(true)}>
                  Change Password
                </Button>
              </div>
            ) : (
              <form onSubmit={handleChangePassword} className="space-y-4">
                <div className="p-3 bg-blue-500/10 rounded-lg text-sm text-blue-600 dark:text-blue-400">
                  <p className="font-medium">Password Policy</p>
                  <ul className="mt-1 list-disc list-inside text-xs">
                    <li>Minimum 8 characters</li>
                    <li>Cannot reuse your last 5 passwords</li>
                  </ul>
                </div>
                <Input
                  label="Current Password"
                  type={showPasswords.current ? 'text' : 'password'}
                  value={passwordData.currentPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                  leftIcon={<Lock size={18} />}
                  rightIcon={
                    <button
                      type="button"
                      onClick={() => setShowPasswords({ ...showPasswords, current: !showPasswords.current })}
                      className="hover:text-[var(--color-text-primary)]"
                    >
                      {showPasswords.current ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  }
                />
                <Input
                  label="New Password"
                  type={showPasswords.new ? 'text' : 'password'}
                  value={passwordData.newPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                  leftIcon={<Lock size={18} />}
                  rightIcon={
                    <button
                      type="button"
                      onClick={() => setShowPasswords({ ...showPasswords, new: !showPasswords.new })}
                      className="hover:text-[var(--color-text-primary)]"
                    >
                      {showPasswords.new ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  }
                />
                {passwordData.newPassword && (
                  <PasswordStrength password={passwordData.newPassword} />
                )}
                <Input
                  label="Confirm New Password"
                  type={showPasswords.confirm ? 'text' : 'password'}
                  value={passwordData.confirmPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                  leftIcon={<Lock size={18} />}
                  rightIcon={
                    <button
                      type="button"
                      onClick={() => setShowPasswords({ ...showPasswords, confirm: !showPasswords.confirm })}
                      className="hover:text-[var(--color-text-primary)]"
                    >
                      {showPasswords.confirm ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  }
                />
                <div className="flex gap-3">
                  <Button 
                    type="button" 
                    variant="ghost" 
                    onClick={() => {
                      setShowPasswordChange(false);
                      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
                    }}
                    className="flex-1"
                  >
                    Cancel
                  </Button>
                  <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
                    Update Password
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>

        {/* Session Management */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/10">
                <LogOut size={20} className="text-red-500" />
              </div>
              <CardTitle>Active Sessions</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {sessionsLoading ? (
                <div className="text-center py-4 text-[var(--color-text-muted)]">Loading sessions...</div>
              ) : activeSessions.length === 0 ? (
                <p className="text-sm text-[var(--color-text-secondary)] text-center py-4">
                  No active sessions found
                </p>
              ) : (
                <>
                  <div className="space-y-2">
                    {activeSessions.map((session: Session) => (
                      <div key={session.id} className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              {session.is_current && (
                                <Badge variant="success" size="sm">Current Session</Badge>
                              )}
                              {session.fingerprint && (
                                <span className="text-xs text-[var(--color-text-muted)] font-mono">
                                  {session.fingerprint.substring(0, 8)}...
                                </span>
                              )}
                            </div>
                            <div className="text-sm text-[var(--color-text-secondary)] space-y-1">
                              <div>
                                Created: {new Date(session.created_at).toLocaleString()}
                              </div>
                              <div>
                                Expires: {new Date(session.expires_at).toLocaleString()}
                              </div>
                            </div>
                          </div>
                          {!session.is_current && !session.revoked && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="shrink-0 text-red-500 hover:text-red-600 hover:bg-red-500/10"
                              onClick={() => revokeSessionMutation.mutate(session.id)}
                              disabled={revokeSessionMutation.isPending}
                            >
                              Revoke
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="pt-4 border-t border-[var(--color-border-light)]">
                    <p className="text-sm text-[var(--color-text-secondary)] mb-3">
                      If you suspect unauthorized access, you can revoke all active sessions across all devices. 
                      This will log you out from all devices including this one.
                    </p>
                    <Button 
                      variant="outline" 
                      className="w-full text-red-500 border-red-500 hover:bg-red-500 hover:text-white"
                      onClick={() => setConfirmRevokeAll(true)}
                    >
                      Revoke All Sessions
                    </Button>
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Login History */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
              <Clock size={20} className="text-[#D4D4D4]" />
            </div>
            <CardTitle>Recent Login History</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {historyLoading ? (
            <div className="text-center py-8 text-[var(--color-text-muted)]">Loading...</div>
          ) : loginHistory.length === 0 ? (
            <p className="text-[var(--color-text-secondary)] text-center py-8">
              No login history available
            </p>
          ) : (
            <div className="space-y-3">
              {loginHistory.slice(0, 10).map((entry) => (
                <div key={entry.id} className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        {entry.status === 'success' ? (
                          <Badge variant="success" size="sm">
                            <CheckCircle size={12} className="mr-1" />
                            Success
                          </Badge>
                        ) : (
                          <Badge variant="error" size="sm">
                            <AlertCircle size={12} className="mr-1" />
                            {entry.status}
                          </Badge>
                        )}
                        {entry.login_method && (
                          <Badge variant="default" size="sm">{entry.login_method}</Badge>
                        )}
                      </div>
                      <div className="text-sm text-[var(--color-text-secondary)] space-y-1">
                        {entry.ip_address && (
                          <div className="flex items-center gap-1">
                            <Globe size={12} />
                            {entry.ip_address}
                          </div>
                        )}
                        {entry.location_city && entry.location_country && (
                          <div className="flex items-center gap-1">
                            <MapPin size={12} />
                            {entry.location_city}, {entry.location_country}
                          </div>
                        )}
                        <div className="flex items-center gap-1">
                          <Clock size={12} />
                          {new Date(entry.created_at).toLocaleString()}
                        </div>
                        {entry.failure_reason && (
                          <div className="text-red-500 text-xs mt-1">
                            {entry.failure_reason}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Device Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
              <Smartphone size={20} className="text-[#D4D4D4]" />
            </div>
            <CardTitle>Trusted Devices ({devices.length})</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {devicesLoading ? (
            <div className="text-center py-8 text-[var(--color-text-muted)]">Loading...</div>
          ) : devices.length === 0 ? (
            <p className="text-[var(--color-text-secondary)] text-center py-8">
              No devices registered
            </p>
          ) : (
            <div className="space-y-3">
              {devices.map((device) => (
                <div key={device.id} className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        {device.device_type === 'mobile' ? (
                          <Smartphone size={20} className="text-[var(--color-text-muted)]" />
                        ) : (
                          <Monitor size={20} className="text-[var(--color-text-muted)]" />
                        )}
                        <span className="font-medium text-[var(--color-text-primary)]">
                          {device.device_name || 'Unknown Device'}
                        </span>
                        {device.is_current && (
                          <Badge variant="success" size="sm">Current</Badge>
                        )}
                        {device.is_trusted && (
                          <Badge variant="default" size="sm">Trusted</Badge>
                        )}
                      </div>
                      <div className="text-sm text-[var(--color-text-secondary)] space-y-1">
                        {device.browser && device.os && (
                          <div>{device.browser} on {device.os}</div>
                        )}
                        {device.ip_address && (
                          <div className="flex items-center gap-1">
                            <Globe size={12} />
                            {device.ip_address}
                          </div>
                        )}
                        {device.location_city && device.location_country && (
                          <div className="flex items-center gap-1">
                            <MapPin size={12} />
                            {device.location_city}, {device.location_country}
                          </div>
                        )}
                        {device.last_seen_at && (
                          <div className="flex items-center gap-1">
                            <Clock size={12} />
                            Last seen: {new Date(device.last_seen_at).toLocaleString()}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!device.is_trusted ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => trustDeviceMutation.mutate(device.id)}
                          disabled={trustDeviceMutation.isPending}
                        >
                          Trust
                        </Button>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => untrustDeviceMutation.mutate(device.id)}
                          disabled={untrustDeviceMutation.isPending}
                        >
                          Untrust
                        </Button>
                      )}
                      {/* MFA Trust Revocation - when MFA is enabled and device has fingerprint */}
                      {isMfaEnabled && device.device_fingerprint && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revokeMfaTrustMutation.mutate(device.device_fingerprint!)}
                          disabled={revokeMfaTrustMutation.isPending}
                          title="Revoke MFA Trust - require MFA on next login"
                        >
                          <Key size={14} className="mr-1" />
                          Revoke MFA
                        </Button>
                      )}
                      {!device.is_current && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setConfirmRemoveDevice(device)}
                          className="text-red-500 hover:text-red-600"
                        >
                          <Trash2 size={16} />
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Backup Codes Modal */}
      {showBackupCodes && backupCodes && (
        <Modal
          isOpen={showBackupCodes}
          onClose={() => {
            setShowBackupCodes(false);
            setBackupCodes(null);
          }}
          title="Backup Codes"
          size="md"
        >
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <div className="flex gap-3">
                <AlertCircle className="text-yellow-500 shrink-0" size={20} />
                <div>
                  <p className="text-sm font-medium text-[var(--color-text-primary)]">
                    Save these codes now!
                  </p>
                  <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                    These codes can be used to access your account if you lose access to your authenticator app. Each code can only be used once.
                  </p>
                </div>
              </div>
            </div>
            <div className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
              <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                {backupCodes.map((code, index) => (
                  <div key={index} className="p-2 bg-[var(--color-surface)] rounded text-center">
                    {code}
                  </div>
                ))}
              </div>
            </div>
            <div className="flex justify-end pt-4">
              <Button variant="primary" onClick={() => {
                setShowBackupCodes(false);
                setBackupCodes(null);
              }}>
                I've Saved Them
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Disable MFA Modal */}
      <Modal
        isOpen={showDisableMfa}
        onClose={() => {
          setShowDisableMfa(false);
          setDisableMfaCode('');
        }}
        title="Disable Two-Factor Authentication"
        size="md"
      >
        <form onSubmit={handleDisableMfa} className="space-y-4">
          <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
            <div className="flex gap-3">
              <AlertCircle className="text-red-500 shrink-0" size={20} />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Warning: Disabling MFA
                </p>
                <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                  Your account will be less secure. Enter your verification code to confirm.
                </p>
              </div>
            </div>
          </div>
          <Input
            label="Verification Code"
            placeholder="Enter 6-digit code"
            value={disableMfaCode}
            onChange={(e) => setDisableMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            maxLength={6}
            className="text-center tracking-widest text-lg"
            required
          />
          <div className="flex gap-3 pt-4">
            <Button 
              type="button" 
              variant="ghost" 
              onClick={() => {
                setShowDisableMfa(false);
                setDisableMfaCode('');
              }}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary"
              className="flex-1"
              isLoading={disableMfaMutation.isPending}
              disabled={disableMfaCode.length !== 6}
            >
              Disable MFA
            </Button>
          </div>
        </form>
      </Modal>

      {/* Confirmation Dialogs */}
      <ConfirmDialog
        isOpen={confirmRevokeAll}
        onClose={() => setConfirmRevokeAll(false)}
        onConfirm={() => revokeAllSessionsMutation.mutate()}
        title="Revoke All Sessions"
        message="Are you sure you want to log out of all devices? This will require you to log in again on all devices including this one."
        confirmText="Revoke All"
        variant="danger"
      />


      <ConfirmDialog
        isOpen={!!confirmRemoveDevice}
        onClose={() => setConfirmRemoveDevice(null)}
        onConfirm={() => confirmRemoveDevice && removeDeviceMutation.mutate(confirmRemoveDevice.id)}
        title="Remove Device"
        message="Are you sure you want to remove this device? This action cannot be undone."
        confirmText="Remove"
        variant="danger"
      />
    </div>
  );
}

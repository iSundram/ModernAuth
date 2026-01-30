import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Shield, Smartphone, Mail, Fingerprint, CheckCircle, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Badge } from '../ui';
import { authService } from '../../api/services';

interface MFAStatusOverviewProps {
  onRefresh?: () => void;
}

export function MFAStatusOverview({ onRefresh }: MFAStatusOverviewProps) {
  const { data: mfaStatus, isLoading, refetch } = useQuery({
    queryKey: ['mfa-status'],
    queryFn: () => authService.getMfaStatus(),
    retry: false,
  });

  useEffect(() => {
    if (onRefresh) {
      refetch();
    }
  }, [onRefresh, refetch]);

  if (isLoading) {
    return (
      <div className="animate-pulse space-y-3">
        <div className="h-20 bg-[var(--color-surface-hover)] rounded-lg"></div>
      </div>
    );
  }

  const methods = [
    { 
      key: 'totp', 
      name: 'Authenticator App', 
      icon: Smartphone, 
      enabled: mfaStatus?.totp_enabled,
      description: 'Use an app like Google Authenticator'
    },
    { 
      key: 'email', 
      name: 'Email', 
      icon: Mail, 
      enabled: mfaStatus?.email_enabled,
      description: 'Receive codes via email'
    },
    { 
      key: 'webauthn', 
      name: 'Passkeys', 
      icon: Fingerprint, 
      enabled: mfaStatus?.webauthn_enabled,
      description: 'Use biometrics or security keys'
    },
  ];

  const enabledCount = methods.filter(m => m.enabled).length;
  const hasAnyMfa = enabledCount > 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${hasAnyMfa ? 'bg-green-500/10' : 'bg-yellow-500/10'}`}>
              <Shield size={20} className={hasAnyMfa ? 'text-green-500' : 'text-yellow-500'} />
            </div>
            <div>
              <CardTitle>MFA Status</CardTitle>
              <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                {hasAnyMfa 
                  ? `${enabledCount} method${enabledCount > 1 ? 's' : ''} enabled` 
                  : 'No MFA methods enabled'}
              </p>
            </div>
          </div>
          {hasAnyMfa ? (
            <Badge variant="success" size="sm">
              <CheckCircle size={12} className="mr-1" />
              Protected
            </Badge>
          ) : (
            <Badge variant="warning" size="sm">
              <AlertCircle size={12} className="mr-1" />
              At Risk
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {methods.map((method) => {
            const Icon = method.icon;
            return (
              <div 
                key={method.key}
                className={`p-4 rounded-lg border ${
                  method.enabled 
                    ? 'bg-green-500/5 border-green-500/20' 
                    : 'bg-[var(--color-surface-hover)] border-[var(--color-border)]'
                }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <Icon size={18} className={method.enabled ? 'text-green-500' : 'text-[var(--color-text-muted)]'} />
                  <span className="font-medium text-[var(--color-text-primary)]">{method.name}</span>
                  {method.enabled && (
                    <CheckCircle size={14} className="text-green-500 ml-auto" />
                  )}
                </div>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  {method.description}
                </p>
                {mfaStatus?.preferred_method === method.key && (
                  <Badge variant="primary" size="sm" className="mt-2">
                    Preferred
                  </Badge>
                )}
              </div>
            );
          })}
        </div>

        {mfaStatus && mfaStatus.backup_codes_remaining !== undefined && (
          <div className="mt-4 pt-4 border-t border-[var(--color-border-light)]">
            <div className="flex items-center justify-between">
              <span className="text-sm text-[var(--color-text-secondary)]">
                Backup codes remaining
              </span>
              <span className={`font-medium ${
                mfaStatus.backup_codes_remaining <= 2 
                  ? 'text-red-500' 
                  : 'text-[var(--color-text-primary)]'
              }`}>
                {mfaStatus.backup_codes_remaining}
              </span>
            </div>
            {mfaStatus.backup_codes_remaining <= 2 && (
              <p className="text-xs text-yellow-500 mt-1">
                Consider generating new backup codes
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

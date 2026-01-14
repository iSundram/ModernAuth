import { useQuery } from '@tanstack/react-query';
import {
  Globe,
  CheckCircle,
  XCircle,
  Shield,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Badge, LoadingBar } from '../../components/ui';
import { authService } from '../../api/services';

export function AdminOAuthPage() {
  const { data: providerData, isLoading } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: () => authService.getOAuthProviders(),
  });

  const providers = providerData?.providers || [];

  const providerInfo: Record<string, { icon: string, description: string }> = {
    google: {
      icon: "https://www.google.com/favicon.ico",
      description: "Allow users to sign in with their Google accounts."
    },
    github: {
      icon: "https://github.com/favicon.ico",
      description: "Allow users to sign in with their GitHub accounts."
    },
    microsoft: {
      icon: "https://www.microsoft.com/favicon.ico",
      description: "Allow users to sign in with their Microsoft accounts."
    }
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading} message="Loading OAuth providers..." />
      
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">OAuth Providers</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          View and monitor configured third-party authentication providers.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {['google', 'github', 'microsoft'].map((p) => {
          const isConfigured = providers.includes(p);
          const info = providerInfo[p] || { icon: '', description: 'Third-party OAuth provider.' };
          
          return (
            <Card key={p} className={!isConfigured ? 'opacity-60' : ''}>
              <CardHeader className="flex flex-row items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-[var(--color-surface-hover)] flex items-center justify-center border border-[var(--color-border)] overflow-hidden">
                    {info.icon ? (
                      <img src={info.icon} alt={p} className="w-6 h-6" />
                    ) : (
                      <Globe size={20} className="text-[var(--color-text-muted)]" />
                    )}
                  </div>
                  <div>
                    <CardTitle className="capitalize">{p}</CardTitle>
                    <p className="text-xs text-[var(--color-text-muted)]">OAuth 2.0</p>
                  </div>
                </div>
                {isConfigured ? (
                  <Badge variant="success" size="sm">
                    <CheckCircle size={12} className="mr-1" />
                    Configured
                  </Badge>
                ) : (
                  <Badge variant="default" size="sm">
                    <XCircle size={12} className="mr-1" />
                    Not Configured
                  </Badge>
                )}
              </CardHeader>
              <CardContent>
                <p className="text-sm text-[var(--color-text-secondary)] mb-4">
                  {info.description}
                </p>
                {!isConfigured && (
                  <div className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
                    <p className="text-xs text-[var(--color-text-muted)]">
                      To enable {p} login, provide the required client credentials in your server environment variables.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Security Note */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <Shield size={20} className="text-[var(--color-info)]" />
            <CardTitle>Security Configuration</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-[var(--color-text-secondary)]">
            All OAuth flows use secure state parameters and PKCE where applicable. 
            Redirect URLs are strictly validated against configured allow-lists.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

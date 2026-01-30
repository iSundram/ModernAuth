import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link2, Unlink, ExternalLink } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button, Badge, ConfirmDialog } from '../ui';
import { useToast } from '../ui/Toast';
import { oauthService, authService } from '../../api/services';

// Provider icons and colors
const providerConfig: Record<string, { name: string; color: string; icon: string }> = {
  google: { name: 'Google', color: '#4285F4', icon: '🔵' },
  github: { name: 'GitHub', color: '#24292e', icon: '⚫' },
  microsoft: { name: 'Microsoft', color: '#00a4ef', icon: '🔷' },
  facebook: { name: 'Facebook', color: '#1877f2', icon: '🔵' },
  twitter: { name: 'Twitter', color: '#1da1f2', icon: '🐦' },
  apple: { name: 'Apple', color: '#000000', icon: '🍎' },
  linkedin: { name: 'LinkedIn', color: '#0077b5', icon: '🔗' },
};

export function LinkedAccounts() {
  const [confirmUnlink, setConfirmUnlink] = useState<string | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Get available providers
  const { data: providersData } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: () => authService.getOAuthProviders(),
  });

  // Linked providers are not yet supported by the backend linking API.
  // Keep this query as a simple empty list to avoid network calls.
  const { data: linkedProviders = [], isLoading } = useQuery({
    queryKey: ['linked-providers'],
    queryFn: async () => [],
  });

  // Unlink mutation
  const unlinkMutation = useMutation({
    mutationFn: async (_provider: string) => {
      throw new Error('OAuth account unlinking is not yet available.');
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['linked-providers'] });
      showToast({ title: 'Success', message: 'Account unlinked successfully', type: 'success' });
      setConfirmUnlink(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to unlink account', type: 'error' });
    },
  });

  // Link provider handler
  const handleLink = async () => {
    showToast({
      title: 'Not available',
      message: 'Connected accounts are not yet available in this deployment.',
      type: 'info',
    });
  };

  const availableProviders = providersData?.providers || [];
  const linkedProviderNames = linkedProviders.map(p => p.provider);
  const unlinkedProviders = availableProviders.filter(p => !linkedProviderNames.includes(p));

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
            <Link2 size={20} className="text-[#D4D4D4]" />
          </div>
          <div>
            <CardTitle>Connected Accounts</CardTitle>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1">
              Link your social accounts for easier sign-in
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="text-center py-4 text-[var(--color-text-muted)]">
            Loading connected accounts...
          </div>
        ) : (
          <div className="space-y-4">
            {/* Linked Accounts */}
            {linkedProviders.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-[var(--color-text-primary)]">
                  Linked Accounts
                </h4>
                {linkedProviders.map((linked) => {
                  const config = providerConfig[linked.provider] || { 
                    name: linked.provider, 
                    color: '#666', 
                    icon: '🔗' 
                  };
                  return (
                    <div 
                      key={linked.provider}
                      className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-xl">{config.icon}</span>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-[var(--color-text-primary)]">
                              {config.name}
                            </span>
                            <Badge variant="success" size="sm">Connected</Badge>
                          </div>
                          {linked.email && (
                            <p className="text-xs text-[var(--color-text-secondary)]">
                              {linked.email}
                            </p>
                          )}
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirmUnlink(linked.provider)}
                        className="text-red-500 hover:text-red-600"
                      >
                        <Unlink size={16} />
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Available to Link */}
            {unlinkedProviders.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-[var(--color-text-primary)]">
                  Available to Connect
                </h4>
                {unlinkedProviders.map((provider) => {
                  const config = providerConfig[provider] || { 
                    name: provider, 
                    color: '#666', 
                    icon: '🔗' 
                  };
                  return (
                    <div 
                      key={provider}
                      className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-xl">{config.icon}</span>
                        <span className="font-medium text-[var(--color-text-primary)]">
                          {config.name}
                        </span>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleLink}
                      >
                        <ExternalLink size={14} className="mr-1" />
                        Connect
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}

            {linkedProviders.length === 0 && unlinkedProviders.length === 0 && (
              <p className="text-center text-sm text-[var(--color-text-muted)] py-4">
                No social login providers are configured
              </p>
            )}
          </div>
        )}
      </CardContent>

      <ConfirmDialog
        isOpen={!!confirmUnlink}
        onClose={() => setConfirmUnlink(null)}
        onConfirm={() => { if (confirmUnlink) unlinkMutation.mutate(confirmUnlink); }}
        title="Unlink Account"
        message={`Are you sure you want to unlink your ${providerConfig[confirmUnlink || '']?.name || confirmUnlink} account? You won't be able to use it to sign in until you link it again.`}
        confirmText="Unlink"
        loading={unlinkMutation.isPending}
        variant="danger"
      />
    </Card>
  );
}

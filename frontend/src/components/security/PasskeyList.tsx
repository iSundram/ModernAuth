import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Fingerprint, Trash2, Clock, Key } from 'lucide-react';
import { Button, ConfirmDialog } from '../ui';
import { useToast } from '../ui/Toast';
import { authService } from '../../api/services';
import type { WebAuthnCredential } from '../../types';

export function PasskeyList() {
  const [confirmDelete, setConfirmDelete] = useState<WebAuthnCredential | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  const { data: credentials = [], isLoading } = useQuery({
    queryKey: ['webauthn-credentials'],
    queryFn: () => authService.webauthnListCredentials(),
  });

  const deleteMutation = useMutation({
  mutationFn: (credentialId: string) => authService.webauthnDeleteCredential(credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webauthn-credentials'] });
      queryClient.invalidateQueries({ queryKey: ['mfa-status'] });
      showToast({ title: 'Success', message: 'Passkey deleted successfully', type: 'success' });
      setConfirmDelete(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete passkey', type: 'error' });
    },
  });

  if (isLoading) {
    return (
      <div className="text-center py-4 text-[var(--color-text-muted)]">
        Loading passkeys...
      </div>
    );
  }

  if (credentials.length === 0) {
    return (
      <div className="text-center py-6">
        <Fingerprint size={32} className="mx-auto text-[var(--color-text-muted)] mb-2" />
        <p className="text-sm text-[var(--color-text-secondary)]">
          No passkeys registered yet
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="space-y-3">
        {credentials.map((credential) => (
          <div 
            key={credential.id} 
            className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
                  <Key size={18} className="text-[#D4D4D4]" />
                </div>
                <div>
                  <p className="font-medium text-[var(--color-text-primary)]">
                    {credential.name || 'Unnamed Passkey'}
                  </p>
                  <div className="text-sm text-[var(--color-text-secondary)] space-y-1 mt-1">
                    <div className="flex items-center gap-1">
                      <Clock size={12} />
                      Created: {new Date(credential.created_at).toLocaleDateString()}
                    </div>
                    {credential.last_used_at && (
                      <div className="flex items-center gap-1">
                        <Clock size={12} />
                        Last used: {new Date(credential.last_used_at).toLocaleDateString()}
                      </div>
                    )}
                  </div>
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setConfirmDelete(credential)}
                className="text-red-500 hover:text-red-600"
              >
                <Trash2 size={16} />
              </Button>
            </div>
          </div>
        ))}
      </div>

      <ConfirmDialog
        isOpen={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => { if (confirmDelete) deleteMutation.mutate(confirmDelete.id); }}
        title="Delete Passkey"
        message={`Are you sure you want to delete "${confirmDelete?.name}"? You won't be able to use this passkey to sign in anymore.`}
        confirmText="Delete"
        loading={deleteMutation.isPending}
        variant="danger"
      />
    </>
  );
}

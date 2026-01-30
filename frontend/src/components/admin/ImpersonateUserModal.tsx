import { useState } from 'react';
import { UserMinus, AlertTriangle } from 'lucide-react';
import { Button, Modal, Input } from '../ui';
import { adminService } from '../../api/services';
import { useToast } from '../ui/Toast';
import { useAuth } from '../../hooks/useAuth';
import type { User } from '../../types';

interface ImpersonateUserModalProps {
  isOpen: boolean;
  onClose: () => void;
  user: User | null;
}

export function ImpersonateUserModal({ isOpen, onClose, user }: ImpersonateUserModalProps) {
  const [reason, setReason] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { showToast } = useToast();
  const { setTokens } = useAuth();

  if (!user) return null;

  const handleImpersonate = async () => {
    setIsLoading(true);
    try {
      const result = await adminService.impersonateUser(user.id, reason || undefined);

      // Store the new tokens
      localStorage.setItem('access_token', result.tokens.access_token);
      localStorage.setItem('refresh_token', result.tokens.refresh_token);
      
      // Store original admin tokens to restore later (optional enhancement)
      // localStorage.setItem('admin_access_token', currentAccessToken);

      // Update auth context
      setTokens(result.tokens.access_token, result.tokens.refresh_token);

      showToast({
        title: 'Impersonation Started',
        message: `You are now impersonating ${user.email}`,
        type: 'success'
      });

      // Redirect to user dashboard
      window.location.href = '/user';
    } catch (err) {
      showToast({
        title: 'Impersonation Failed',
        message: err instanceof Error ? err.message : 'Failed to start impersonation',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Impersonate User">
      <div className="space-y-6">
        <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg flex gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-amber-800 font-medium mb-1">
              Security Notice
            </p>
            <p className="text-sm text-amber-700">
              Impersonation sessions are logged and audited. You will be acting as this user
              with their permissions. This session will automatically expire.
            </p>
          </div>
        </div>

        <div className="p-4 bg-[var(--color-background)] rounded-lg">
          <h4 className="font-medium text-[var(--color-text-primary)] mb-2">
            Target User
          </h4>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-[var(--color-primary)]/10 flex items-center justify-center">
              <UserMinus className="w-5 h-5 text-[var(--color-primary)]" />
            </div>
            <div>
              <p className="font-medium text-[var(--color-text-primary)]">
                {user.email}
              </p>
              <p className="text-sm text-[var(--color-text-muted)]">
                {user.first_name} {user.last_name}
              </p>
            </div>
          </div>
        </div>

        <Input
          label="Reason for impersonation (optional)"
          placeholder="e.g., Support ticket #12345"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          helperText="This will be logged for audit purposes"
        />

        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={handleImpersonate}
            isLoading={isLoading}
            variant="primary"
            className="bg-amber-500 hover:bg-amber-600"
            leftIcon={<UserMinus size={18} />}
          >
            Start Impersonation
          </Button>
        </div>
      </div>
    </Modal>
  );
}

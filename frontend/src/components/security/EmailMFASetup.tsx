import { useState } from 'react';
import { Mail, CheckCircle, AlertCircle } from 'lucide-react';
import { Button, Modal } from '../ui';
import { useToast } from '../ui/Toast';
import { authService } from '../../api/services';

interface EmailMFASetupProps {
  isEnabled: boolean;
  onSuccess?: () => void;
}

export function EmailMFASetup({ isEnabled, onSuccess }: EmailMFASetupProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const { showToast } = useToast();

  const handleEnable = async () => {
    setIsLoading(true);
    try {
      await authService.enableEmailMfa();
      showToast({ 
        title: 'Success', 
        message: 'Email MFA has been enabled. You will receive a code via email when signing in.', 
        type: 'success' 
      });
      onSuccess?.();
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to enable email MFA', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisable = async () => {
    setIsLoading(true);
    try {
      await authService.disableEmailMfa();
      showToast({ 
        title: 'Success', 
        message: 'Email MFA has been disabled', 
        type: 'success' 
      });
      setShowConfirm(false);
      onSuccess?.();
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to disable email MFA', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <div className="flex items-start gap-4 p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
        <div className="p-2 rounded-lg bg-blue-500/10">
          <Mail size={20} className="text-blue-500" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium text-[var(--color-text-primary)]">Email Verification</h4>
            {isEnabled && (
              <span className="inline-flex items-center gap-1 text-xs text-green-500">
                <CheckCircle size={12} />
                Enabled
              </span>
            )}
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mb-3">
            Receive a verification code via email when you sign in.
          </p>
          {isEnabled ? (
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setShowConfirm(true)}
            >
              Disable Email MFA
            </Button>
          ) : (
            <Button 
              variant="primary" 
              size="sm"
              onClick={handleEnable}
              isLoading={isLoading}
            >
              Enable Email MFA
            </Button>
          )}
        </div>
      </div>

      <Modal
        isOpen={showConfirm}
        onClose={() => setShowConfirm(false)}
        title="Disable Email MFA"
        size="sm"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
            <div className="flex gap-2">
              <AlertCircle className="text-yellow-500 shrink-0" size={16} />
              <p className="text-sm text-[var(--color-text-secondary)]">
                Disabling email MFA will make your account less secure. Make sure you have 
                another MFA method enabled.
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <Button 
              variant="ghost" 
              onClick={() => setShowConfirm(false)} 
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleDisable} 
              isLoading={isLoading}
              className="flex-1 bg-red-500 hover:bg-red-600"
            >
              Disable
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

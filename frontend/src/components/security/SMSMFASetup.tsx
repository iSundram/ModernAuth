import { useState } from 'react';
import { MessageSquare, CheckCircle, AlertCircle } from 'lucide-react';
import { Button, Input, Modal } from '../ui';
import { useToast } from '../ui/Toast';
import { authService } from '../../api/services';

interface SMSMFASetupProps {
  isEnabled: boolean;
  currentPhone?: string;
  onSuccess?: () => void;
}

export function SMSMFASetup({ isEnabled, currentPhone, onSuccess }: SMSMFASetupProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [phoneNumber, setPhoneNumber] = useState(currentPhone || '');
  const { showToast } = useToast();

  const handleEnable = async () => {
    if (!phoneNumber.trim()) {
      showToast({ 
        title: 'Error', 
        message: 'Please enter a phone number', 
        type: 'error' 
      });
      return;
    }

    setIsLoading(true);
    try {
      await authService.enableSmsMfa(phoneNumber);
      showToast({ 
        title: 'Success', 
        message: 'SMS MFA has been enabled. You will receive a code via SMS when signing in.', 
        type: 'success' 
      });
      setShowSetup(false);
      onSuccess?.();
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to enable SMS MFA', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisable = async () => {
    setIsLoading(true);
    try {
      await authService.disableSmsMfa();
      showToast({ 
        title: 'Success', 
        message: 'SMS MFA has been disabled', 
        type: 'success' 
      });
      setShowConfirm(false);
      onSuccess?.();
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to disable SMS MFA', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <div className="flex items-start gap-4 p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]">
        <div className="p-2 rounded-lg bg-purple-500/10">
          <MessageSquare size={20} className="text-purple-500" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-medium text-[var(--color-text-primary)]">SMS Verification</h4>
            {isEnabled && (
              <span className="inline-flex items-center gap-1 text-xs text-green-500">
                <CheckCircle size={12} />
                Enabled
              </span>
            )}
          </div>
          <p className="text-sm text-[var(--color-text-secondary)] mb-3">
            Receive a verification code via SMS when you sign in.
          </p>
          {isEnabled ? (
            <div className="space-y-2">
              {currentPhone && (
                <p className="text-sm text-[var(--color-text-muted)]">
                  Codes sent to: {currentPhone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')}
                </p>
              )}
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => setShowConfirm(true)}
              >
                Disable SMS MFA
              </Button>
            </div>
          ) : (
            <Button 
              variant="primary" 
              size="sm"
              onClick={() => setShowSetup(true)}
            >
              Enable SMS MFA
            </Button>
          )}
        </div>
      </div>

      {/* Setup Modal */}
      <Modal
        isOpen={showSetup}
        onClose={() => setShowSetup(false)}
        title="Enable SMS MFA"
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Enter your phone number to receive verification codes via SMS.
          </p>
          <Input
            label="Phone Number"
            placeholder="+1234567890"
            value={phoneNumber}
            onChange={(e) => setPhoneNumber(e.target.value)}
            leftIcon={<MessageSquare size={18} />}
          />
          <p className="text-xs text-[var(--color-text-muted)]">
            Include country code (e.g., +1 for US). Standard SMS rates may apply.
          </p>
          <div className="flex gap-3">
            <Button 
              variant="ghost" 
              onClick={() => setShowSetup(false)} 
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleEnable} 
              isLoading={isLoading}
              disabled={!phoneNumber.trim()}
              className="flex-1"
            >
              Enable
            </Button>
          </div>
        </div>
      </Modal>

      {/* Disable Confirmation Modal */}
      <Modal
        isOpen={showConfirm}
        onClose={() => setShowConfirm(false)}
        title="Disable SMS MFA"
        size="sm"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
            <div className="flex gap-2">
              <AlertCircle className="text-yellow-500 shrink-0" size={16} />
              <p className="text-sm text-[var(--color-text-secondary)]">
                Disabling SMS MFA will make your account less secure. Make sure you have 
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

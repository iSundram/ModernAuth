import { useState } from 'react';
import { Smartphone, Mail, MessageSquare, Fingerprint, CheckCircle } from 'lucide-react';
import { Button, Modal } from '../ui';
import { useToast } from '../ui/Toast';
import { authService } from '../../api/services';

interface MFAPreferencesSelectorProps {
  currentPreferred: 'totp' | 'email' | 'sms' | 'webauthn' | null;
  enabledMethods: {
    totp: boolean;
    email: boolean;
    sms: boolean;
    webauthn: boolean;
  };
  onSuccess?: () => void;
}

export function MFAPreferencesSelector({ 
  currentPreferred, 
  enabledMethods, 
  onSuccess 
}: MFAPreferencesSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [selected, setSelected] = useState<'totp' | 'email' | 'sms' | 'webauthn' | null>(currentPreferred);
  const { showToast } = useToast();

  const methods = [
    { key: 'totp' as const, name: 'Authenticator App', icon: Smartphone, enabled: enabledMethods.totp },
    { key: 'email' as const, name: 'Email', icon: Mail, enabled: enabledMethods.email },
    { key: 'sms' as const, name: 'SMS', icon: MessageSquare, enabled: enabledMethods.sms },
    { key: 'webauthn' as const, name: 'Passkey', icon: Fingerprint, enabled: enabledMethods.webauthn },
  ];

  const handleSave = async () => {
    if (!selected) return;
    
    setIsLoading(true);
    try {
      await authService.setPreferredMfaMethod(selected);
      showToast({ 
        title: 'Success', 
        message: 'Preferred MFA method updated', 
        type: 'success' 
      });
      setIsOpen(false);
      onSuccess?.();
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to update preference', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const enabledMethodsCount = Object.values(enabledMethods).filter(Boolean).length;
  if (enabledMethodsCount < 2) {
    return null; // No point in showing if only one or zero methods enabled
  }

  return (
    <>
      <Button 
        variant="outline" 
        size="sm"
        onClick={() => setIsOpen(true)}
      >
        Set Preferred Method
      </Button>

      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="Preferred MFA Method"
        size="md"
      >
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Select your preferred method for two-factor authentication. This will be used by default when signing in.
          </p>

          <div className="space-y-2">
            {methods.map((method) => {
              const Icon = method.icon;
              const isSelected = selected === method.key;
              const isCurrent = currentPreferred === method.key;
              
              return (
                <button
                  key={method.key}
                  disabled={!method.enabled}
                  onClick={() => setSelected(method.key)}
                  className={`w-full p-4 rounded-lg border text-left transition-all ${
                    !method.enabled 
                      ? 'opacity-50 cursor-not-allowed bg-[var(--color-surface-hover)] border-[var(--color-border)]'
                      : isSelected
                        ? 'bg-[var(--color-primary)]/10 border-[var(--color-primary)]'
                        : 'bg-[var(--color-surface-hover)] border-[var(--color-border)] hover:border-[var(--color-primary)]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${isSelected ? 'bg-[var(--color-primary)]/20' : 'bg-[var(--color-primary-dark)]'}`}>
                      <Icon size={18} className={isSelected ? 'text-[var(--color-primary)]' : 'text-[#D4D4D4]'} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-[var(--color-text-primary)]">
                          {method.name}
                        </span>
                        {isCurrent && (
                          <span className="text-xs text-green-500">(Current)</span>
                        )}
                        {!method.enabled && (
                          <span className="text-xs text-[var(--color-text-muted)]">(Not enabled)</span>
                        )}
                      </div>
                    </div>
                    {isSelected && (
                      <CheckCircle size={20} className="text-[var(--color-primary)]" />
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          <div className="flex gap-3 pt-2">
            <Button 
              variant="ghost" 
              onClick={() => setIsOpen(false)} 
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleSave} 
              isLoading={isLoading}
              disabled={!selected || selected === currentPreferred}
              className="flex-1"
            >
              Save Preference
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

import { useState } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import { Fingerprint, Plus, AlertCircle } from 'lucide-react';
import { Button, Input, Modal } from '../ui';
import { useToast } from '../ui/Toast';
import { authService } from '../../api/services';

interface PasskeySetupProps {
  onSuccess?: () => void;
}

export function PasskeySetup({ onSuccess }: PasskeySetupProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');
  const { showToast } = useToast();

  const handleRegister = async () => {
    if (!passkeyName.trim()) {
      showToast({ title: 'Error', message: 'Please enter a name for your passkey', type: 'error' });
      return;
    }

    setIsLoading(true);
    try {
      // Get registration options (and challenge id) from server
      const { options, challenge_id } = await authService.webauthnRegisterBegin(passkeyName);
      
      // SimpleWebAuthn browser expects { optionsJSON }; backend returns { options }
      const credential = await startRegistration({ optionsJSON: options });
      
      // Backend expects credential with attestationObject, clientDataJSON at top level
      const credentialForBackend = {
        id: credential.id,
        rawId: credential.rawId,
        type: credential.type,
        attestationObject: credential.response.attestationObject,
        clientDataJSON: credential.response.clientDataJSON,
      };
      
      await authService.webauthnRegisterFinish(challenge_id, passkeyName, credentialForBackend);
      
      showToast({ title: 'Success', message: 'Passkey registered successfully!', type: 'success' });
      setIsOpen(false);
      setPasskeyName('');
      onSuccess?.();
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        showToast({ title: 'Cancelled', message: 'Passkey registration was cancelled', type: 'info' });
      } else {
        showToast({ 
          title: 'Error', 
          message: error instanceof Error ? error.message : 'Failed to register passkey', 
          type: 'error' 
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Button 
        onClick={() => setIsOpen(true)} 
        variant="outline" 
        className="w-full"
      >
        <Plus size={18} className="mr-2" />
        Add Passkey
      </Button>

      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="Register New Passkey"
        size="md"
      >
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <div className="flex gap-3">
              <Fingerprint className="text-blue-500 shrink-0" size={24} />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Passwordless Authentication
                </p>
                <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                  Passkeys use your device's biometrics (Face ID, Touch ID, Windows Hello) 
                  or security keys for secure, passwordless login.
                </p>
              </div>
            </div>
          </div>

          <Input
            label="Passkey Name"
            placeholder="e.g., MacBook Pro, iPhone, Security Key"
            value={passkeyName}
            onChange={(e) => setPasskeyName(e.target.value)}
            autoFocus
          />

          <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
            <div className="flex gap-2">
              <AlertCircle className="text-yellow-500 shrink-0" size={16} />
              <p className="text-xs text-[var(--color-text-secondary)]">
                Your browser will prompt you to verify your identity using biometrics or a security key.
              </p>
            </div>
          </div>

          <div className="flex gap-3">
            <Button 
              variant="ghost" 
              onClick={() => setIsOpen(false)} 
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleRegister} 
              isLoading={isLoading}
              className="flex-1"
            >
              Register Passkey
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

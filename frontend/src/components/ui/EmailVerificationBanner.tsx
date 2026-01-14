import { useState } from 'react';
import { AlertTriangle, Send } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { authService } from '../../api/services';
import { Button } from './Button';
import { useToast } from './Toast';

export function EmailVerificationBanner() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [isSending, setIsSending] = useState(false);

  if (!user || user.is_email_verified) {
    return null;
  }

  const handleResend = async () => {
    setIsSending(true);
    try {
      await authService.sendVerification();
      showToast({ 
        title: 'Email Sent', 
        message: 'Verification email has been sent to your inbox.', 
        type: 'success' 
      });
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to send verification email', 
        type: 'error' 
      });
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="bg-[var(--color-warning)]/10 border-b border-[var(--color-warning)]/20 px-6 py-3">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <AlertTriangle size={20} className="text-[var(--color-warning)] shrink-0" />
          <p className="text-sm text-[var(--color-text-primary)]">
            Your email address <span className="font-medium">({user.email})</span> is not verified. 
            Please verify your email to access all features.
          </p>
        </div>
        <Button 
          size="sm" 
          variant="outline" 
          onClick={handleResend}
          isLoading={isSending}
          className="whitespace-nowrap bg-white hover:bg-[var(--color-warning)]/10 border-[var(--color-warning)] text-[var(--color-warning-dark)]"
        >
          <Send size={14} className="mr-2" />
          Resend Verification
        </Button>
      </div>
    </div>
  );
}

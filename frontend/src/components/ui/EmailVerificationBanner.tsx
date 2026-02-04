import { useState, useEffect } from 'react';
import { AlertTriangle, Send } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { authService } from '../../api/services';
import { Button } from './Button';
import { useToast } from './Toast';

const RESEND_COOLDOWN_SECONDS = 60;

export function EmailVerificationBanner() {
  const { user } = useAuth();
  const { showToast } = useToast();
  const [isSending, setIsSending] = useState(false);
  const [cooldownRemaining, setCooldownRemaining] = useState(0);

  // Cooldown timer effect
  useEffect(() => {
    if (cooldownRemaining <= 0) return;
    const timer = setInterval(() => {
      setCooldownRemaining((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldownRemaining]);

  if (!user || user.is_email_verified) {
    return null;
  }

  const handleResend = async () => {
    if (cooldownRemaining > 0) return;
    
    setIsSending(true);
    try {
      await authService.sendVerification();
      setCooldownRemaining(RESEND_COOLDOWN_SECONDS);
      showToast({ 
        title: 'Email Sent', 
        message: 'Verification email has been sent to your inbox.', 
        type: 'success' 
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to send verification email';
      // Handle rate limit response
      if (errorMessage.toLowerCase().includes('rate limit') || errorMessage.includes('429')) {
        setCooldownRemaining(RESEND_COOLDOWN_SECONDS);
      }
      showToast({ 
        title: 'Error', 
        message: errorMessage, 
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
          disabled={cooldownRemaining > 0}
          className="whitespace-nowrap bg-white hover:bg-[var(--color-warning)]/10 border-[var(--color-warning)] text-[var(--color-warning-dark)]"
        >
          <Send size={14} className="mr-2" />
          {cooldownRemaining > 0 ? `Resend in ${cooldownRemaining}s` : 'Resend Verification'}
        </Button>
      </div>
    </div>
  );
}

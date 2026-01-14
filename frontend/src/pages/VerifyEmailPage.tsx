import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle, XCircle } from 'lucide-react';
import { Button, LoadingBar } from '../components/ui';
import { authService } from '../api/services';

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying');
  const [message, setMessage] = useState('Verifying your email address...');
  const navigate = useNavigate();

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage('Invalid or missing verification token.');
      return;
    }

    const verify = async () => {
      try {
        await authService.verifyEmail(token);
        setStatus('success');
        setMessage('Your email has been successfully verified.');
      } catch (error) {
        setStatus('error');
        setMessage(error instanceof Error ? error.message : 'Failed to verify email.');
      }
    };

    verify();
  }, [token]);

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      <LoadingBar isLoading={status === 'verifying'} message="Verifying..." />

      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)] text-center">
            <div className="flex justify-center mb-6">
              {status === 'verifying' && (
                <div className="w-16 h-16 rounded-full border-4 border-[var(--color-primary)] border-t-transparent animate-spin" />
              )}
              {status === 'success' && (
                <div className="p-3 rounded-full bg-[var(--color-success)]/10 text-[var(--color-success)]">
                  <CheckCircle size={48} />
                </div>
              )}
              {status === 'error' && (
                <div className="p-3 rounded-full bg-[var(--color-error)]/10 text-[var(--color-error)]">
                  <XCircle size={48} />
                </div>
              )}
            </div>

            <h2 className="text-2xl font-bold text-[var(--color-text-primary)] mb-2">
              {status === 'verifying' ? 'Verifying Email' : status === 'success' ? 'Email Verified' : 'Verification Failed'}
            </h2>
            
            <p className="text-[var(--color-text-secondary)] mb-8">
              {message}
            </p>

            <div className="space-y-4">
              <Button
                variant="primary"
                size="lg"
                className="w-full"
                onClick={() => navigate(status === 'success' ? '/' : '/login')}
              >
                {status === 'success' ? 'Continue to Dashboard' : 'Back to Login'}
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

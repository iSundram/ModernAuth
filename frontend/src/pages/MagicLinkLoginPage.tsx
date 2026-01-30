import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Input, LoadingBar } from '../components/ui';
import { Mail, Wand2, ArrowLeft, CheckCircle } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/Toast';
import { authService } from '../api/services';

export function MagicLinkLoginPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const { showToast } = useToast();
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  if (isAuthenticated) {
    navigate('/');
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email) {
      setError('Please enter your email address');
      return;
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    setIsLoading(true);

    try {
      await authService.sendMagicLink(email);
      setSuccess(true);
      showToast({ 
        title: 'Magic Link Sent', 
        message: 'Check your email for a sign-in link', 
        type: 'success' 
      });
    } catch (err) {
      // Always show success to prevent email enumeration
      setSuccess(true);
    } finally {
      setIsLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen bg-[var(--color-background)]">
        <div className="min-h-screen flex items-center justify-center p-4">
          <div className="absolute inset-0 overflow-hidden">
            <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
            <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
          </div>

          <div className="w-full max-w-md relative z-10">
            <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
              <div className="flex flex-col items-center">
                <div className="w-16 h-16 rounded-full bg-[var(--color-success)]/10 flex items-center justify-center mb-4">
                  <CheckCircle className="w-8 h-8 text-[var(--color-success)]" />
                </div>
                <h2 className="text-2xl font-bold text-[var(--color-text-primary)] text-center mb-2">
                  Check your email
                </h2>
                <p className="text-[var(--color-text-secondary)] text-center mb-6">
                  We've sent a magic sign-in link to <strong>{email}</strong>
                </p>
                <p className="text-sm text-[var(--color-text-muted)] text-center mb-6">
                  The link will expire in 15 minutes. If you don't see the email, check your spam folder.
                </p>
                <div className="flex flex-col gap-3 w-full">
                  <Button
                    variant="outline"
                    onClick={() => { setSuccess(false); setEmail(''); }}
                    leftIcon={<ArrowLeft size={18} />}
                    className="w-full"
                  >
                    Try a different email
                  </Button>
                  <Link to="/login" className="text-center">
                    <span className="text-sm text-[var(--color-info)] hover:underline">
                      Back to sign in
                    </span>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      <LoadingBar isLoading={isLoading} message="Sending magic link..." />

      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
            <div className="flex flex-col items-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500 to-indigo-600 shadow-2xl mb-4">
                <Wand2 className="w-8 h-8 text-white" />
              </div>
              <h2 className="text-3xl font-bold text-[var(--color-text-primary)] text-center font-poppins">
                Magic Link
              </h2>
              <p className="text-base text-[var(--color-text-secondary)] text-center mt-4">
                Sign in without a password
              </p>
            </div>

            {error && (
              <div className="mb-6 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <Input
                label="Email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                leftIcon={<Mail size={18} />}
                autoComplete="email"
                autoFocus
              />

              <Button
                type="submit"
                variant="primary"
                size="lg"
                isLoading={isLoading}
                className="w-full"
                leftIcon={<Wand2 size={18} />}
              >
                Send Magic Link
              </Button>
            </form>
            
            <div className="mt-6 text-center border-t border-[var(--color-border-light)] pt-6">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Prefer to use a password?{' '}
                <Link to="/login" className="text-[var(--color-primary)] font-medium hover:underline">
                  Sign in with password
                </Link>
              </p>
            </div>
          </div>

          <p className="text-center mt-6 text-sm text-[var(--color-text-muted)]">
            © 2024 ModernAuth. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}

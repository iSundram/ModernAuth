import { useEffect, useState, useRef } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { LoadingBar } from '../components/ui';
import { CheckCircle, XCircle, Wand2 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/Toast';
import { authService } from '../api/services';

export function MagicLinkVerifyPage() {
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState('');
  const [isNewUser, setIsNewUser] = useState(false);
  const { setUser, setTokens } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const verificationAttempted = useRef(false);

  const token = searchParams.get('token');

  useEffect(() => {
    if (!token) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Handle missing token on mount
      setStatus('error');
      setErrorMessage('No magic link token provided');
      return;
    }

    // Prevent double verification in React Strict Mode
    if (verificationAttempted.current) {
      return;
    }
    verificationAttempted.current = true;

    const verifyToken = async () => {
      try {
        const result = await authService.verifyMagicLink(token, true);
        
        // Store tokens
        localStorage.setItem('access_token', result.tokens.access_token);
        localStorage.setItem('refresh_token', result.tokens.refresh_token);
        
        // Update auth context
        setTokens(result.tokens.access_token, result.tokens.refresh_token);
        setUser(result.user);
        
        setIsNewUser(result.is_new_user);
        setStatus('success');
        
        showToast({
          title: result.is_new_user ? 'Welcome!' : 'Welcome back!',
          message: result.is_new_user ? 'Your account has been created' : 'You have been signed in',
          type: 'success'
        });

        // Redirect after short delay
        setTimeout(() => {
          navigate('/user', { replace: true });
        }, 2000);
      } catch (err) {
        setStatus('error');
        if (err instanceof Error) {
          if (err.message.includes('expired')) {
            setErrorMessage('This magic link has expired. Please request a new one.');
          } else if (err.message.includes('used')) {
            setErrorMessage('This magic link has already been used. Please request a new one.');
          } else {
            setErrorMessage(err.message);
          }
        } else {
          setErrorMessage('Failed to verify magic link');
        }
      }
    };

    verifyToken();
  }, [token, navigate, setUser, setTokens, showToast]);

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      <LoadingBar isLoading={status === 'loading'} message="Signing you in..." />
      
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
            <div className="flex flex-col items-center">
              {status === 'loading' && (
                <>
                  <div className="w-16 h-16 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center mb-4 animate-pulse">
                    <Wand2 className="w-8 h-8 text-white" />
                  </div>
                  <h2 className="text-2xl font-bold text-[var(--color-text-primary)] text-center mb-2">
                    Verifying your magic link...
                  </h2>
                  <p className="text-[var(--color-text-secondary)] text-center">
                    Please wait while we sign you in
                  </p>
                </>
              )}

              {status === 'success' && (
                <>
                  <div className="w-16 h-16 rounded-full bg-[var(--color-success)]/10 flex items-center justify-center mb-4">
                    <CheckCircle className="w-8 h-8 text-[var(--color-success)]" />
                  </div>
                  <h2 className="text-2xl font-bold text-[var(--color-text-primary)] text-center mb-2">
                    {isNewUser ? 'Account Created!' : 'Signed In!'}
                  </h2>
                  <p className="text-[var(--color-text-secondary)] text-center mb-4">
                    {isNewUser 
                      ? 'Your account has been created and you are now signed in.'
                      : 'You have been successfully signed in.'}
                  </p>
                  <p className="text-sm text-[var(--color-text-muted)]">
                    Redirecting to dashboard...
                  </p>
                </>
              )}

              {status === 'error' && (
                <>
                  <div className="w-16 h-16 rounded-full bg-[var(--color-error)]/10 flex items-center justify-center mb-4">
                    <XCircle className="w-8 h-8 text-[var(--color-error)]" />
                  </div>
                  <h2 className="text-2xl font-bold text-[var(--color-text-primary)] text-center mb-2">
                    Link Invalid
                  </h2>
                  <p className="text-[var(--color-text-secondary)] text-center mb-6">
                    {errorMessage}
                  </p>
                  <div className="flex flex-col gap-3 w-full">
                    <Link 
                      to="/login/magic-link" 
                      className="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-[var(--color-primary)] hover:bg-[var(--color-primary-dark)] transition-colors"
                    >
                      Request a new magic link
                    </Link>
                    <Link to="/login" className="text-center">
                      <span className="text-sm text-[var(--color-info)] hover:underline">
                        Back to sign in
                      </span>
                    </Link>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

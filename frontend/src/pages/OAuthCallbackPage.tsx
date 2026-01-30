import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { Button } from '../components/ui';

export function OAuthCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('Processing authentication...');

  useEffect(() => {
    const handleCallback = async () => {
      const error = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');
      const action = searchParams.get('action'); // 'login' or 'link'
      const success = searchParams.get('success');

      if (error) {
        setStatus('error');
        setMessage(errorDescription || error || 'Authentication failed');
        return;
      }

      if (success === 'true') {
        setStatus('success');
        
        if (action === 'link') {
          setMessage('Account linked successfully!');
          // Redirect to connected accounts after a delay
          setTimeout(() => navigate('/user/connected-accounts'), 2000);
        } else {
          setMessage('Login successful!');
          // Redirect to dashboard - page reload will refresh auth state
          setTimeout(() => {
            window.location.href = '/';
          }, 2000);
        }
      } else {
        setStatus('error');
        setMessage('Authentication response was incomplete');
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  return (
    <div className="min-h-screen bg-[var(--color-background)] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)] text-center">
          {/* Logo */}
          <div className="flex justify-center mb-6">
            <div className="w-16 h-16 rounded-2xl bg-white shadow-2xl overflow-hidden p-2">
              <img src="/logo.svg" alt="Logo" className="w-full h-full object-contain" />
            </div>
          </div>

          {/* Status Icon */}
          <div className="flex justify-center mb-4">
            {status === 'loading' && (
              <div className="w-16 h-16 rounded-full bg-blue-500/10 flex items-center justify-center">
                <Loader2 size={32} className="text-blue-500 animate-spin" />
              </div>
            )}
            {status === 'success' && (
              <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center">
                <CheckCircle size={32} className="text-green-500" />
              </div>
            )}
            {status === 'error' && (
              <div className="w-16 h-16 rounded-full bg-red-500/10 flex items-center justify-center">
                <XCircle size={32} className="text-red-500" />
              </div>
            )}
          </div>

          {/* Title */}
          <h2 className="text-xl font-bold text-[var(--color-text-primary)] mb-2">
            {status === 'loading' && 'Authenticating'}
            {status === 'success' && 'Success'}
            {status === 'error' && 'Authentication Failed'}
          </h2>

          {/* Message */}
          <p className="text-[var(--color-text-secondary)] mb-6">
            {message}
          </p>

          {/* Actions */}
          {status === 'error' && (
            <div className="space-y-3">
              <Button
                variant="primary"
                className="w-full"
                onClick={() => navigate('/login')}
              >
                Try Again
              </Button>
              <Button
                variant="ghost"
                className="w-full"
                onClick={() => navigate('/')}
              >
                Go to Dashboard
              </Button>
            </div>
          )}

          {status === 'success' && (
            <p className="text-sm text-[var(--color-text-muted)]">
              Redirecting...
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

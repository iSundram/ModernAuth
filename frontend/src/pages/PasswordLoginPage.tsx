import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { startAuthentication } from '@simplewebauthn/browser';
import { Button, Input, LoadingBar } from '../components/ui';
import { Lock, ArrowLeft, Eye, EyeOff, ShieldCheck, Mail, Fingerprint, Key, Clock, Smartphone } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/Toast';
import { authService } from '../api/services';

export function PasswordLoginPage() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  
  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaUserId, setMfaUserId] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaMethod, setMfaMethod] = useState<'totp' | 'email' | 'sms' | 'backup' | 'passkey'>('totp');
  const [mfaAvailableMethods, setMfaAvailableMethods] = useState<string[]>([]); // from backend when mfa_required
  const [emailMfaSent, setEmailMfaSent] = useState(false);
  const [smsMfaSent, setSmsMfaSent] = useState(false);
  const [trustDevice, setTrustDevice] = useState(false);
  const [totpCountdown, setTotpCountdown] = useState(30);

  // TOTP countdown timer - 30 second window
  useEffect(() => {
    if (!mfaRequired || mfaMethod !== 'totp') return;

    const calculateRemainingTime = () => {
      const now = Math.floor(Date.now() / 1000);
      return 30 - (now % 30);
    };

    setTotpCountdown(calculateRemainingTime());

    const interval = setInterval(() => {
      setTotpCountdown(calculateRemainingTime());
    }, 1000);

    return () => clearInterval(interval);
  }, [mfaRequired, mfaMethod]);

  const { login, loginMfa, completeLogin, isAuthenticated } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
      return;
    }

    // Retrieve email from session storage
    const storedEmail = sessionStorage.getItem('loginEmail');
    if (!storedEmail) {
      // If no email, redirect back to email login
      navigate('/login');
      return;
    }
    setEmail(storedEmail);
  }, [navigate, isAuthenticated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!password) {
      setError('Please enter your password');
      return;
    }

    setIsLoading(true);
    
    try {
      const result = await login({ email, password });
      
      if (result && result.mfa_required) {
        setMfaRequired(true);
        setMfaUserId(result.user_id);
        const methods = result.methods ?? ['totp', 'email', 'webauthn'];
        setMfaAvailableMethods(methods);
        // Map backend preferred_method (webauthn) to UI (passkey); default to totp if preferred not available
        const preferred = result.preferred_method ?? 'totp';
        const preferredUi = preferred === 'webauthn' ? 'passkey' : preferred as 'totp' | 'email' | 'sms' | 'passkey';
        setMfaMethod(methods.includes(preferred) ? preferredUi : (methods.includes('totp') ? 'totp' : methods.includes('email') ? 'email' : methods.includes('sms') ? 'sms' : 'passkey'));
        setIsLoading(false);
        return;
      }
      
      // Clear session storage
      sessionStorage.removeItem('loginEmail');
      
      showToast({ title: 'Success', message: 'Successfully logged in!', type: 'success' });
      
      // Navigate to dashboard
      navigate('/');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid password';
      setError(errorMessage);
      showToast({ title: 'Login Failed', message: errorMessage, type: 'error' });
    } finally {
      if (!mfaRequired) {
        setIsLoading(false);
      }
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (mfaMethod === 'backup') {
      const normalized = mfaCode?.trim().replace(/-/g, '').toLowerCase() ?? '';
      if (normalized.length < 8) {
        setError('Backup code must be 8 characters (e.g. xxxx-xxxx)');
        return;
      }
    } else if (!mfaCode || mfaCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setIsLoading(true);

    try {
      if (mfaMethod === 'email') {
        const res = await authService.verifyEmailMfa(mfaUserId, mfaCode);
        completeLogin(res);
      } else if (mfaMethod === 'sms') {
        const res = await authService.verifySmsMfa(mfaUserId, mfaCode);
        completeLogin(res);
      } else if (mfaMethod === 'backup') {
        const backupCodeNormalized = mfaCode.trim().replace(/-/g, '').toLowerCase();
        const res = await authService.loginWithBackupCode(mfaUserId, backupCodeNormalized);
        completeLogin(res);
      } else {
        await loginMfa(mfaUserId, mfaCode);
      }
      
      // Clear session storage
      sessionStorage.removeItem('loginEmail');
      
      showToast({ title: 'Success', message: 'Successfully logged in!', type: 'success' });
      navigate('/');
    } catch (err) {
       const errorMessage = err instanceof Error ? err.message : 'Invalid MFA code';
       setError(errorMessage);
       showToast({ title: 'MFA Failed', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendEmailCode = async () => {
    setIsLoading(true);
    try {
      await authService.sendEmailMfaCode(mfaUserId);
      setEmailMfaSent(true);
      showToast({ title: 'Code Sent', message: 'Check your email for the verification code', type: 'success' });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send email code';
      setError(errorMessage);
      showToast({ title: 'Error', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendSmsCode = async () => {
    setIsLoading(true);
    try {
      await authService.sendSmsMfaCode(mfaUserId);
      setSmsMfaSent(true);
      showToast({ title: 'Code Sent', message: 'Check your phone for the verification code', type: 'success' });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send SMS code';
      setError(errorMessage);
      showToast({ title: 'Error', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setIsLoading(true);
    setError('');
    
    try {
      // Get authentication options (and challenge id) from server
      const { options, challenge_id } = await authService.webauthnLoginBegin(mfaUserId);
      
      // SimpleWebAuthn browser expects { optionsJSON }; backend returns JSON-serialized options
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const credential = await startAuthentication({ optionsJSON: options as any });
      
      // Backend expects credential with authenticatorData, clientDataJSON, signature at top level
      const credentialForBackend = {
        id: credential.id,
        rawId: credential.rawId,
        type: credential.type,
        authenticatorData: credential.response.authenticatorData,
        clientDataJSON: credential.response.clientDataJSON,
        signature: credential.response.signature,
        userHandle: credential.response.userHandle ?? '',
      };
      
      const res = await authService.webauthnLoginFinish(mfaUserId, challenge_id, credentialForBackend);
      completeLogin(res);
      
      // Clear session storage
      sessionStorage.removeItem('loginEmail');
      
      showToast({ title: 'Success', message: 'Successfully logged in!', type: 'success' });
      navigate('/');
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'NotAllowedError') {
        showToast({ title: 'Cancelled', message: 'Passkey authentication was cancelled', type: 'info' });
      } else {
        const errorMessage = error instanceof Error ? error.message : 'Passkey authentication failed';
        setError(errorMessage);
        showToast({ title: 'Error', message: errorMessage, type: 'error' });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleBack = () => {
    // Clear session storage and go back
    sessionStorage.removeItem('loginEmail');
    navigate('/login');
  };

  const maskEmail = (email: string) => {
    const [username, domain] = email.split('@');
    if (username.length <= 3) return email;
    
    const masked = username.substring(0, 3) + '*'.repeat(username.length - 3);
    return `${masked}@${domain}`;
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      {/* Progress Bar - Only top bar, no overlay */}
      <LoadingBar isLoading={isLoading} message={mfaRequired ? "Verifying..." : "Signing in..."} />

      {/* Background Pattern */}
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          {/* Login Box */}
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
          {/* Logo inside box */}
          <div className="flex flex-col items-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white shadow-2xl mb-4 overflow-hidden p-2">
              <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
            </div>
            <h2 className="text-3xl font-bold text-[var(--color-text-primary)] text-center font-poppins">
              {mfaRequired ? 'Two-Factor Authentication' : 'Sign In'}
            </h2>
            <p className="text-base text-[var(--color-text-secondary)] text-center mt-4">
              {mfaRequired ? 'Enter verification code' : 'Welcome back'}
            </p>
            <p className="text-sm text-[var(--color-text-muted)] text-center">
              {email && maskEmail(email)}
            </p>
          </div>

            {error && (
              <div className="mb-6 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}

            {!mfaRequired ? (
              <form onSubmit={handleSubmit} className="space-y-6">
                <Input
                  label="Password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  leftIcon={<Lock size={18} />}
                  rightIcon={
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="hover:text-[var(--color-text-primary)] transition-colors"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  }
                  autoComplete="current-password"
                  autoFocus
                />

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleBack}
                    className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
                  >
                    <ArrowLeft size={16} />
                    Back
                  </button>
                  
                  <Link
                    to="/forgot-password"
                    className="text-sm text-[var(--color-info)] hover:text-[var(--color-info-dark)] transition-colors"
                  >
                    Forgot password?
                  </Link>
                </div>

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  className="w-full"
                  isLoading={isLoading}
                >
                  Sign in
                </Button>
              </form>
            ) : (
              <div className="space-y-6">
                {/* Preferred method form shown first; "Try another way" switches method */}
                {/* TOTP / Email Code / Backup Form */}
                {(mfaMethod === 'totp' || mfaMethod === 'email' || mfaMethod === 'sms' || mfaMethod === 'backup') && (
                  <form onSubmit={handleMfaSubmit} className="space-y-4">
                    {mfaMethod === 'email' && !emailMfaSent ? (
                      <div className="space-y-4">
                        <p className="text-sm text-[var(--color-text-secondary)] text-center">
                          We'll send a verification code to your email address.
                        </p>
                        <Button
                          type="button"
                          variant="primary"
                          size="lg"
                          className="w-full"
                          onClick={handleSendEmailCode}
                          isLoading={isLoading}
                        >
                          Send Code
                        </Button>
                      </div>
                    ) : mfaMethod === 'sms' && !smsMfaSent ? (
                      <div className="space-y-4">
                        <p className="text-sm text-[var(--color-text-secondary)] text-center">
                          We'll send a verification code to your phone number.
                        </p>
                        <Button
                          type="button"
                          variant="primary"
                          size="lg"
                          className="w-full"
                          onClick={handleSendSmsCode}
                          isLoading={isLoading}
                        >
                          Send SMS Code
                        </Button>
                      </div>
                    ) : (
                      <>
                        <div className="space-y-4">
                          <Input
                            label={mfaMethod === 'backup' ? 'Backup Code' : 'Verification Code'}
                            type="text"
                            placeholder={mfaMethod === 'backup' ? 'Enter backup code' : '000000'}
                            value={mfaCode}
                            onChange={(e) => setMfaCode(
                              mfaMethod === 'backup' 
                                ? e.target.value.toUpperCase().slice(0, 12)
                                : e.target.value.replace(/\D/g, '').slice(0, 6)
                            )}
                            leftIcon={mfaMethod === 'backup' ? <Key size={18} /> : <ShieldCheck size={18} />}
                            autoComplete="one-time-code"
                            className={mfaMethod === 'backup' ? 'font-mono' : 'text-center tracking-widest text-lg'}
                            autoFocus
                          />

                          {mfaMethod === 'totp' && (
                            <div className={`flex items-center justify-center gap-2 text-sm transition-colors ${totpCountdown <= 10 ? 'text-[var(--color-error)] animate-pulse' : 'text-[var(--color-text-secondary)]'}`}>
                              <Clock size={14} />
                              <span>Code expires in {totpCountdown}s</span>
                            </div>
                          )}
                        </div>

                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={trustDevice}
                            onChange={(e) => setTrustDevice(e.target.checked)}
                            className="w-4 h-4 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
                          />
                          <span className="text-sm text-[var(--color-text-secondary)]">
                            Trust this device for 30 days
                          </span>
                        </label>

                        <Button
                          type="submit"
                          variant="primary"
                          size="lg"
                          className="w-full"
                          isLoading={isLoading}
                        >
                          Verify
                        </Button>
                      </>
                    )}
                  </form>
                )}

                {/* Passkey Authentication */}
                {mfaMethod === 'passkey' && (
                  <div className="space-y-4">
                    <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20 text-center">
                      <Fingerprint size={32} className="mx-auto text-blue-500 mb-2" />
                      <p className="text-sm text-[var(--color-text-secondary)]">
                        Use your passkey (Face ID, Touch ID, Windows Hello, or security key) to verify.
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="primary"
                      size="lg"
                      className="w-full"
                      onClick={handlePasskeyLogin}
                      isLoading={isLoading}
                    >
                      <Fingerprint size={18} className="mr-2" />
                      Use Passkey
                    </Button>
                  </div>
                )}

                {/* Try another way: show only methods the user has enabled */}
                {(() => {
                  const showMethod = (key: string) => {
                    if (mfaAvailableMethods.length === 0) return true;
                    const backendKey = key === 'passkey' ? 'webauthn' : key;
                    return mfaAvailableMethods.includes(backendKey);
                  };
                  const hasOtherMethods = (showMethod('totp') && mfaMethod !== 'totp') || (showMethod('email') && mfaMethod !== 'email') || (showMethod('sms') && mfaMethod !== 'sms') || (showMethod('webauthn') && mfaMethod !== 'passkey');
                  if (!hasOtherMethods) return null;
                  return (
                    <>
                      <p className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                        Try another way
                      </p>
                      <div className="flex gap-2 p-1 bg-[var(--color-surface-hover)] rounded-lg">
                        {showMethod('totp') && (
                          <button
                            type="button"
                            onClick={() => { setMfaMethod('totp'); setMfaCode(''); setError(''); }}
                            className={`flex-1 flex items-center justify-center gap-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                              mfaMethod === 'totp' ? 'bg-white text-[var(--color-text-primary)] shadow-sm' : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'
                            }`}
                          >
                            <ShieldCheck size={16} />
                            App
                          </button>
                        )}
                        {showMethod('email') && (
                          <button
                            type="button"
                            onClick={() => { setMfaMethod('email'); setMfaCode(''); setError(''); setEmailMfaSent(false); }}
                            className={`flex-1 flex items-center justify-center gap-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                              mfaMethod === 'email' ? 'bg-white text-[var(--color-text-primary)] shadow-sm' : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'
                            }`}
                          >
                            <Mail size={16} />
                            Email
                          </button>
                        )}
                        {showMethod('sms') && (
                          <button
                            type="button"
                            onClick={() => { setMfaMethod('sms'); setMfaCode(''); setError(''); setSmsMfaSent(false); }}
                            className={`flex-1 flex items-center justify-center gap-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                              mfaMethod === 'sms' ? 'bg-white text-[var(--color-text-primary)] shadow-sm' : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'
                            }`}
                          >
                            <Smartphone size={16} />
                            SMS
                          </button>
                        )}
                        {showMethod('webauthn') && (
                          <button
                            type="button"
                            onClick={() => { setMfaMethod('passkey'); setMfaCode(''); setError(''); }}
                            className={`flex-1 flex items-center justify-center gap-1 py-2 px-3 rounded-md text-sm font-medium transition-colors ${
                              mfaMethod === 'passkey' ? 'bg-white text-[var(--color-text-primary)] shadow-sm' : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'
                            }`}
                          >
                            <Fingerprint size={16} />
                            Passkey
                          </button>
                        )}
                      </div>
                    </>
                  );
                })()}

                {mfaMethod !== 'backup' && (
                  <button 
                    type="button"
                    onClick={() => { setMfaMethod('backup'); setMfaCode(''); setError(''); }}
                    className="w-full text-center text-sm text-[var(--color-info)] hover:text-[var(--color-info-dark)]"
                  >
                    Use a backup code instead
                  </button>
                )}
                   
                <button 
                  type="button"
                  onClick={() => {
                    setMfaRequired(false);
                    setMfaMethod('totp');
                    setMfaCode('');
                    setEmailMfaSent(false);
                    setIsLoading(false);
                  }}
                  className="w-full text-center text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
                >
                  Back to Password
                </button>
              </div>
            )}
           </div>

           {/* Additional footer */}
           <p className="text-center mt-6 text-sm text-[var(--color-text-muted)]">
             © 2024 ModernAuth. All rights reserved.
           </p>
         </div>
       </div>
     </div>
   );
}

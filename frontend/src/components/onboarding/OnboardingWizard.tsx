import { useState, useEffect } from 'react';
import { 
  CheckCircle, 
  Mail, 
  Shield, 
  Fingerprint, 
  ArrowRight, 
  X,
  Sparkles,
  Users,
  Globe,
  Palette
} from 'lucide-react';
import { Button, Modal } from '../ui';
import { useAuth } from '../../hooks/useAuth';
import { authService, tenantService } from '../../api/services';
import { useTenant } from '../../hooks/useTenant';

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  completed: boolean;
  action?: () => void;
  actionLabel?: string;
  optional?: boolean;
}

interface OnboardingWizardProps {
  onComplete?: () => void;
}

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const { user } = useAuth();
  const { tenant } = useTenant();
  const [isOpen, setIsOpen] = useState(false);
  const [mfaStatus, setMfaStatus] = useState<{
    totp_enabled: boolean;
    email_enabled: boolean;
    webauthn_enabled: boolean;
  } | null>(null);
  const [tenantStatus, setTenantStatus] = useState<{
    is_domain_verified: boolean;
    has_users: boolean;
    has_feature_flags: boolean;
    is_complete: boolean;
  } | null>(null);

  // Check if user is tenant admin
  const isTenantAdmin = user?.role === 'admin';

  // Check if onboarding should be shown
  useEffect(() => {
    const checkOnboarding = async () => {
      if (!user) return;

      // Check if user has dismissed onboarding
      const dismissed = localStorage.getItem(`onboarding-dismissed-${user.id}`);
      if (dismissed) return;

      // Fetch MFA status
      let fetchedMfaStatus = mfaStatus;
      try {
        fetchedMfaStatus = await authService.getMfaStatus();
        setMfaStatus(fetchedMfaStatus);
      } catch {
        // Ignore errors
      }

      // Fetch Tenant Status if admin
      let fetchedTenantStatus = tenantStatus;
      if (isTenantAdmin && tenant) {
        try {
          fetchedTenantStatus = await tenantService.getOnboardingStatus(tenant.id);
          setTenantStatus(fetchedTenantStatus);
        } catch {
          // Ignore
        }
      }

      // Show onboarding if email not verified or no MFA
      let needsOnboarding = !user.is_email_verified || 
        (!fetchedMfaStatus?.totp_enabled && !fetchedMfaStatus?.email_enabled && !fetchedMfaStatus?.webauthn_enabled);

      if (isTenantAdmin && fetchedTenantStatus) {
        if (!fetchedTenantStatus.is_complete) {
            needsOnboarding = true;
        }
      }
      
      if (needsOnboarding) {
        // Delay showing to not interrupt initial page load
        setTimeout(() => setIsOpen(true), 1500);
      }
    };

    checkOnboarding();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, tenant?.id, isTenantAdmin]);

  const handleDismiss = () => {
    if (user) {
      localStorage.setItem(`onboarding-dismissed-${user.id}`, 'true');
    }
    setIsOpen(false);
    onComplete?.();
  };

  const handleComplete = () => {
    if (user) {
      localStorage.setItem(`onboarding-dismissed-${user.id}`, 'true');
    }
    setIsOpen(false);
    onComplete?.();
  };

  const userSteps: OnboardingStep[] = [
    {
      id: 'email',
      title: 'Verify Your Email',
      description: 'Confirm your email address to secure your account and enable password recovery.',
      icon: <Mail size={24} />,
      completed: user?.is_email_verified || false,
      action: async () => {
        try {
          await authService.sendVerification();
          alert('Verification email sent! Please check your inbox.');
        } catch {
          alert('Failed to send verification email. Please try again.');
        }
      },
      actionLabel: 'Send Verification Email',
    },
    {
      id: 'mfa',
      title: 'Enable Two-Factor Authentication',
      description: 'Add an extra layer of security using an authenticator app or email codes.',
      icon: <Shield size={24} />,
      completed: mfaStatus?.totp_enabled || mfaStatus?.email_enabled || false,
      action: () => {
        window.location.href = '/user/security';
      },
      actionLabel: 'Set Up MFA',
    },
    {
      id: 'passkey',
      title: 'Add a Passkey',
      description: 'Use biometrics or a security key for passwordless sign-in.',
      icon: <Fingerprint size={24} />,
      completed: mfaStatus?.webauthn_enabled || false,
      action: () => {
        window.location.href = '/user/security';
      },
      actionLabel: 'Add Passkey',
      optional: true,
    },
  ];

  const tenantSteps: OnboardingStep[] = [
      {
          id: 'domain',
          title: 'Verify Domain',
          description: 'Verify your custom domain to enable branded emails and login pages.',
          icon: <Globe size={24} />,
          completed: tenantStatus?.is_domain_verified || false,
          action: () => {
              window.location.href = '/admin/settings';
          },
          actionLabel: 'Verify Domain',
      },
      {
          id: 'users',
          title: 'Invite Team Members',
          description: 'Invite your colleagues to join your tenant.',
          icon: <Users size={24} />,
          completed: tenantStatus?.has_users || false,
          action: () => {
              window.location.href = '/admin/users';
          },
          actionLabel: 'Invite Users',
      },
      {
          id: 'branding',
          title: 'Configure Branding',
          description: 'Customize the look and feel of your emails and login pages.',
          icon: <Palette size={24} />,
          completed: tenantStatus?.has_feature_flags || false, // Using this as proxy for now
          action: () => {
              window.location.href = '/admin/email/branding';
          },
          actionLabel: 'Setup Branding',
      }
  ];

  const steps = isTenantAdmin ? [...userSteps, ...tenantSteps] : userSteps;

  const completedSteps = steps.filter(s => s.completed).length;
  const progress = (completedSteps / steps.length) * 100;

  if (!user || !isOpen) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleDismiss}
      title=""
      size="lg"
    >
      <div className="relative">
        {/* Close button */}
        <button
          onClick={handleDismiss}
          className="absolute right-0 top-0 p-2 text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <X size={20} />
        </button>

        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20 flex items-center justify-center">
            <Sparkles size={32} className="text-[#D4D4D4]" />
          </div>
          <h2 className="text-2xl font-bold text-[var(--color-text-primary)]">
            Welcome to ModernAuth!
          </h2>
          <p className="text-[var(--color-text-secondary)] mt-2">
            Complete these steps to secure your account
          </p>
        </div>

        {/* Progress bar */}
        <div className="mb-8">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-[var(--color-text-secondary)]">
              {completedSteps} of {steps.length} steps completed
            </span>
            <span className="font-medium text-[var(--color-text-primary)]">
              {Math.round(progress)}%
            </span>
          </div>
          <div className="h-2 rounded-full bg-[var(--color-border)] overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-green-500 to-emerald-400 transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Steps */}
        <div className="space-y-4">
          {steps.map((step, index) => (
            <div
              key={step.id}
              className={`p-4 rounded-xl border transition-all ${
                step.completed
                  ? 'bg-green-500/5 border-green-500/20'
                  : index === completedSteps
                  ? 'bg-[var(--color-surface-hover)] border-[var(--color-border)]'
                  : 'bg-[var(--color-surface)] border-[var(--color-border-light)]'
              }`}
            >
              <div className="flex items-start gap-4">
                <div
                  className={`w-12 h-12 shrink-0 rounded-xl flex items-center justify-center ${
                    step.completed
                      ? 'bg-green-500'
                      : 'bg-[var(--color-primary-dark)]'
                  }`}
                >
                  {step.completed ? (
                    <CheckCircle size={24} className="text-white" />
                  ) : (
                    <span className={step.completed ? 'text-white' : 'text-[#D4D4D4]'}>
                      {step.icon}
                    </span>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium text-[var(--color-text-primary)]">
                      {step.title}
                    </h3>
                    {step.optional && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--color-border)] text-[var(--color-text-muted)]">
                        Optional
                      </span>
                    )}
                    {step.completed && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-500">
                        Completed
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                    {step.description}
                  </p>
                  {!step.completed && step.action && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-3"
                      onClick={step.action}
                      rightIcon={<ArrowRight size={14} />}
                    >
                      {step.actionLabel}
                    </Button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="flex justify-between items-center mt-8 pt-6 border-t border-[var(--color-border-light)]">
          <button
            onClick={handleDismiss}
            className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
          >
            Remind me later
          </button>
          {completedSteps === steps.length ? (
            <Button onClick={handleComplete} variant="primary">
              All Done!
            </Button>
          ) : (
            <Button onClick={handleDismiss} variant="ghost">
              Continue to Dashboard
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
}

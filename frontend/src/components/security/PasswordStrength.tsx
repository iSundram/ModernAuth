import { useState, useEffect, useCallback } from 'react';
import { Check, AlertTriangle, Shield, Loader2 } from 'lucide-react';

interface PasswordStrengthProps {
  password: string;
  onBreachCheck?: (isBreached: boolean) => void;
}

interface StrengthRule {
  label: string;
  test: (password: string) => boolean;
}

const rules: StrengthRule[] = [
  { label: 'At least 8 characters', test: (p) => p.length >= 8 },
  { label: 'Contains uppercase letter', test: (p) => /[A-Z]/.test(p) },
  { label: 'Contains lowercase letter', test: (p) => /[a-z]/.test(p) },
  { label: 'Contains number', test: (p) => /\d/.test(p) },
  { label: 'Contains special character', test: (p) => /[!@#$%^&*(),.?":{}|<>]/.test(p) },
];

// Check password against HaveIBeenPwned using k-anonymity
async function checkPasswordBreach(password: string): Promise<{ breached: boolean; count: number }> {
  try {
    // Create SHA-1 hash of password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    
    // Use k-anonymity: only send first 5 characters
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);
    
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    
    if (!response.ok) {
      return { breached: false, count: 0 };
    }
    
    const text = await response.text();
    const lines = text.split('\n');
    
    for (const line of lines) {
      const [hashSuffix, countStr] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        const count = parseInt(countStr.trim(), 10);
        return { breached: count > 0, count };
      }
    }
    
    return { breached: false, count: 0 };
  } catch {
    // Fail silently - don't block user if API is unavailable
    return { breached: false, count: 0 };
  }
}

export function PasswordStrength({ password, onBreachCheck }: PasswordStrengthProps) {
  const [breachStatus, setBreachStatus] = useState<{ checking: boolean; breached: boolean; count: number }>({
    checking: false,
    breached: false,
    count: 0,
  });

  const checkBreach = useCallback(async (pwd: string) => {
    if (pwd.length < 8) {
      setBreachStatus({ checking: false, breached: false, count: 0 });
      onBreachCheck?.(false);
      return;
    }
    
    setBreachStatus(prev => ({ ...prev, checking: true }));
    const result = await checkPasswordBreach(pwd);
    setBreachStatus({ checking: false, ...result });
    onBreachCheck?.(result.breached);
  }, [onBreachCheck]);

  // Debounce the breach check
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (password && password.length >= 8) {
        checkBreach(password);
      } else {
        setBreachStatus({ checking: false, breached: false, count: 0 });
      }
    }, 500);

    return () => clearTimeout(timeoutId);
  }, [password, checkBreach]);

  const passedRules = rules.filter((rule) => rule.test(password));
  const strength = passedRules.length;
  
  const getStrengthColor = () => {
    if (breachStatus.breached) return 'bg-red-500';
    if (strength <= 1) return 'bg-red-500';
    if (strength <= 2) return 'bg-orange-500';
    if (strength <= 3) return 'bg-yellow-500';
    if (strength <= 4) return 'bg-lime-500';
    return 'bg-green-500';
  };

  const getStrengthLabel = () => {
    if (breachStatus.breached) return 'Compromised';
    if (strength <= 1) return 'Very Weak';
    if (strength <= 2) return 'Weak';
    if (strength <= 3) return 'Fair';
    if (strength <= 4) return 'Strong';
    return 'Very Strong';
  };

  if (!password) {
    return null;
  }

  return (
    <div className="space-y-3">
      {/* Breach Warning */}
      {breachStatus.breached && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 flex items-start gap-3">
          <AlertTriangle size={18} className="text-red-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-500">Password found in data breach</p>
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              This password was found {breachStatus.count.toLocaleString()} times in known data breaches. 
              Please choose a different password.
            </p>
          </div>
        </div>
      )}

      {/* Strength Bar */}
      <div className="space-y-1">
        <div className="flex justify-between text-xs">
          <span className="text-[var(--color-text-secondary)]">Password strength</span>
          <span className={`font-medium flex items-center gap-1 ${
            breachStatus.breached ? 'text-red-500' : strength <= 2 ? 'text-red-500' : strength <= 3 ? 'text-yellow-500' : 'text-green-500'
          }`}>
            {breachStatus.checking && <Loader2 size={12} className="animate-spin" />}
            {getStrengthLabel()}
          </span>
        </div>
        <div className="flex gap-1">
          {[1, 2, 3, 4, 5].map((level) => (
            <div
              key={level}
              className={`h-1.5 flex-1 rounded-full transition-colors ${
                level <= strength ? getStrengthColor() : 'bg-[var(--color-border)]'
              }`}
            />
          ))}
        </div>
      </div>

      {/* Rules Checklist */}
      <div className="space-y-1">
        {rules.map((rule, index) => {
          const passed = rule.test(password);
          return (
            <div 
              key={index} 
              className={`flex items-center gap-2 text-xs transition-colors ${
                passed ? 'text-green-500' : 'text-[var(--color-text-muted)]'
              }`}
            >
              <div className={`w-4 h-4 rounded-full flex items-center justify-center ${
                passed ? 'bg-green-500' : 'bg-[var(--color-border)]'
              }`}>
                {passed && <Check size={10} className="text-white" />}
              </div>
              {rule.label}
            </div>
          );
        })}
        
        {/* Breach Check Status */}
        {password.length >= 8 && (
          <div 
            className={`flex items-center gap-2 text-xs transition-colors ${
              breachStatus.checking 
                ? 'text-[var(--color-text-muted)]' 
                : breachStatus.breached 
                  ? 'text-red-500' 
                  : 'text-green-500'
            }`}
          >
            <div className={`w-4 h-4 rounded-full flex items-center justify-center ${
              breachStatus.checking 
                ? 'bg-[var(--color-border)]' 
                : breachStatus.breached 
                  ? 'bg-red-500' 
                  : 'bg-green-500'
            }`}>
              {breachStatus.checking ? (
                <Loader2 size={10} className="animate-spin text-[var(--color-text-muted)]" />
              ) : breachStatus.breached ? (
                <AlertTriangle size={10} className="text-white" />
              ) : (
                <Shield size={10} className="text-white" />
              )}
            </div>
            {breachStatus.checking 
              ? 'Checking breach database...' 
              : breachStatus.breached 
                ? 'Found in data breach' 
                : 'Not found in data breaches'}
          </div>
        )}
      </div>
    </div>
  );
}

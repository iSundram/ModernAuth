import { FC } from 'react';

interface AuthFooterProps {
  className?: string;
}

export const AuthFooter: FC<AuthFooterProps> = ({ className = "mt-8" }) => {
  const currentYear = new Date().getFullYear();
  
  return (
    <p className={`text-center text-sm text-[var(--color-text-muted)] ${className}`}>
      © {currentYear} ModernAuth. All rights reserved.
    </p>
  );
};

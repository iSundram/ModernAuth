import type { ReactNode } from 'react';

type BadgeVariant = 'default' | 'success' | 'warning' | 'error' | 'info' | 'primary';
type BadgeSize = 'sm' | 'md' | 'lg';

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  size?: BadgeSize;
  className?: string;
  dot?: boolean;
}

export function Badge({
  children,
  variant = 'default',
  size = 'md',
  className = '',
  dot = false,
}: BadgeProps) {
  const variantClasses = {
    default: 'bg-[var(--color-gray-light)]/30 text-[var(--color-text-primary)] border-[var(--color-gray-medium)]/30',
    success: 'bg-[var(--color-success)]/20 text-[var(--color-success)] border-[var(--color-success)]/30',
    warning: 'bg-[var(--color-warning)]/20 text-[var(--color-warning)] border-[var(--color-warning)]/30',
    error: 'bg-[var(--color-error)]/20 text-[var(--color-error)] border-[var(--color-error)]/30',
    info: 'bg-[var(--color-info)]/20 text-[var(--color-info)] border-[var(--color-info)]/30',
    primary: 'bg-[var(--color-primary)]/20 text-[var(--color-primary)] border-[var(--color-primary)]/30',
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-2.5 py-1',
    lg: 'text-base px-3 py-1.5',
  };

  const dotColors = {
    default: 'bg-[var(--color-text-secondary)]',
    success: 'bg-[var(--color-success)]',
    warning: 'bg-[var(--color-warning)]',
    error: 'bg-[var(--color-error)]',
    info: 'bg-[var(--color-info)]',
    primary: 'bg-[var(--color-primary)]',
  };

  return (
    <span
      className={`
        inline-flex items-center gap-1.5
        font-medium rounded-full border
        ${variantClasses[variant]}
        ${sizeClasses[size]}
        ${className}
      `}
    >
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotColors[variant]}`} />}
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const statusMap: Record<string, BadgeVariant> = {
    active: 'success',
    inactive: 'default',
    pending: 'warning',
    failed: 'error',
    running: 'success',
    stopped: 'error',
    suspended: 'warning',
  };

  return (
    <Badge variant={statusMap[status.toLowerCase()] || 'default'} size="sm" dot>
      {status}
    </Badge>
  );
}

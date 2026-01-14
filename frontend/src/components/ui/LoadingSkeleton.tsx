interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular';
  width?: string;
  height?: string;
  animation?: 'pulse' | 'wave';
}

export function Skeleton({
  className = '',
  variant = 'rectangular',
  width = '100%',
  height = '1rem',
  animation = 'pulse',
}: SkeletonProps) {
  const variantClasses = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
  };

  const animationClasses = {
    pulse: 'animate-pulse',
    wave: 'animate-shimmer',
  };

  return (
    <div
      className={`
        bg-[var(--color-primary-dark)]/50
        ${variantClasses[variant]}
        ${animationClasses[animation]}
        ${className}
      `}
      style={{ width, height }}
    />
  );
}

export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} height="1.5rem" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} height="2rem" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="bg-[var(--color-surface)] rounded-xl border border-[var(--color-border-light)] p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div className="space-y-2 flex-1">
          <Skeleton width="40%" height="1rem" />
          <Skeleton width="60%" height="2rem" />
        </div>
        <Skeleton variant="circular" width="3rem" height="3rem" />
      </div>
    </div>
  );
}

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <Skeleton width="200px" height="2rem" />
        <Skeleton width="300px" height="1rem" />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <CardSkeleton key={i} />
        ))}
      </div>

      {/* Content */}
      <div className="bg-[var(--color-surface)] rounded-xl border border-[var(--color-border-light)] p-6">
        <Skeleton width="150px" height="1.5rem" className="mb-4" />
        <TableSkeleton />
      </div>
    </div>
  );
}

export function LoadingSkeleton({ className = "" }: { className?: string }) {
  return <Skeleton className={className} />;
}

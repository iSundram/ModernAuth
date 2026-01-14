import type { SelectHTMLAttributes, ReactNode } from 'react';
import { forwardRef, useId } from 'react';
import { ChevronDown } from 'lucide-react';

interface SelectOption {
  value: string | number;
  label: string;
  disabled?: boolean;
}

interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'children'> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: ReactNode;
  options: SelectOption[];
  placeholder?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, helperText, leftIcon, options, placeholder, className = '', id, ...props }, ref) => {
    const generatedId = useId();
    const selectId = id || generatedId;

    return (
      <div className="w-full">
        {label && (
          <label
            htmlFor={selectId}
            className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1.5 transition-colors group-focus-within:text-[var(--color-info)]"
          >
            {label}
          </label>
        )}
        <div className="relative group">
          {leftIcon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] transition-colors group-focus-within:text-[var(--color-info)] pointer-events-none">
              {leftIcon}
            </div>
          )}
          <select
            ref={ref}
            id={selectId}
            className={`
              w-full px-4 py-2.5 rounded-lg
              bg-white border border-[var(--color-border)]
              text-[var(--color-text-primary)]
              transition-all duration-200
              focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/20 focus:border-[var(--color-info)]
              disabled:bg-[var(--color-border-light)] disabled:opacity-60 disabled:cursor-not-allowed
              appearance-none cursor-pointer
              pr-10
              ${leftIcon ? 'pl-10' : ''}
              ${error ? 'border-[var(--color-error)] focus:ring-[var(--color-error)]/20 focus:border-[var(--color-error)]' : ''}
              ${className}
            `}
            {...props}
          >
            {placeholder && (
              <option value="" disabled hidden>
                {placeholder}
              </option>
            )}
            {options.map((option) => (
              <option 
                key={option.value} 
                value={option.value}
                disabled={option.disabled}
                className="py-2"
              >
                {option.label}
              </option>
            ))}
          </select>
          <div className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)] group-focus-within:text-[var(--color-info)] transition-colors pointer-events-none">
            <ChevronDown size={18} />
          </div>
        </div>
        {(error || helperText) && (
          <p
            className={`mt-1.5 text-sm animate-in fade-in slide-in-from-top-1 ${
              error ? 'text-[var(--color-error)]' : 'text-[var(--color-text-muted)]'
            }`}
          >
            {error || helperText}
          </p>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';

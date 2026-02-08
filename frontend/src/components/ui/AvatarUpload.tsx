import { useState, useRef, useCallback } from 'react';
import { Camera, Upload, Trash2, User, X } from 'lucide-react';
import { Button } from './Button';

interface AvatarUploadProps {
  currentUrl?: string;
  name?: string;
  onUpload: (url: string) => void;
  onRemove?: () => void;
}

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_SIZE = 2 * 1024 * 1024; // 2MB

function getInitials(name?: string): string {
  if (!name) return '';
  return name
    .split(' ')
    .map((part) => part[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
}

export function AvatarUpload({ currentUrl, name, onUpload, onRemove }: AvatarUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): string | null => {
    if (!ALLOWED_TYPES.includes(file.type)) {
      return 'Invalid file type. Please use JPG, PNG, GIF, or WebP.';
    }
    if (file.size > MAX_SIZE) {
      return 'File is too large. Maximum size is 2MB.';
    }
    return null;
  };

  const processFile = useCallback((file: File) => {
    setError(null);
    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }

    const reader = new FileReader();
    reader.onloadstart = () => setIsLoading(true);
    reader.onloadend = () => setIsLoading(false);
    reader.onload = (e) => {
      const result = e.target?.result as string;
      setPreviewUrl(result);
    };
    reader.onerror = () => {
      setError('Failed to read file. Please try again.');
      setIsLoading(false);
    };
    reader.readAsDataURL(file);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) {
        processFile(file);
      }
    },
    [processFile]
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        processFile(file);
      }
    },
    [processFile]
  );

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleConfirmUpload = () => {
    if (previewUrl) {
      setIsLoading(true);
      // Simulate a brief delay for UX
      setTimeout(() => {
        onUpload(previewUrl);
        setPreviewUrl(null);
        setIsLoading(false);
      }, 300);
    }
  };

  const handleCancelPreview = () => {
    setPreviewUrl(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRemove = () => {
    if (onRemove) {
      onRemove();
    }
    setPreviewUrl(null);
    setError(null);
  };

  const initials = getInitials(name);
  const displayUrl = previewUrl || currentUrl;

  return (
    <div className="flex flex-col items-center gap-4">
      {/* Avatar Display / Drop Zone */}
      <div
        role="button"
        tabIndex={0}
        onClick={handleClick}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleClick();
          }
        }}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative w-20 h-20 rounded-full cursor-pointer
          transition-all duration-200 group
          ${isDragging ? 'ring-4 ring-[var(--color-info)] ring-offset-2' : ''}
          ${!displayUrl ? 'border-2 border-dashed border-[var(--color-border)] hover:border-[var(--color-info)]' : ''}
        `}
      >
        {displayUrl ? (
          <>
            <img
              src={displayUrl}
              alt="Avatar"
              className="w-full h-full rounded-full object-cover"
            />
            {/* Overlay on hover */}
            <div className="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
              <Camera className="w-6 h-6 text-white" />
            </div>
          </>
        ) : (
          <div className="w-full h-full rounded-full bg-[var(--color-light)] flex items-center justify-center text-[var(--color-text-muted)] group-hover:bg-[var(--color-gray-light)]/30 transition-colors">
            {initials ? (
              <span className="text-xl font-semibold text-[var(--color-text-secondary)]">
                {initials}
              </span>
            ) : (
              <User className="w-8 h-8" />
            )}
          </div>
        )}

        {/* Loading overlay */}
        {isLoading && (
          <div className="absolute inset-0 rounded-full bg-black/50 flex items-center justify-center">
            <svg
              className="animate-spin h-6 w-6 text-white"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>
        )}
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".jpg,.jpeg,.png,.gif,.webp"
        onChange={handleFileSelect}
        className="hidden"
        aria-label="Upload avatar"
      />

      {/* Helper text */}
      <p className="text-xs text-[var(--color-text-muted)] text-center">
        Click or drag & drop
        <br />
        JPG, PNG, GIF, WebP (max 2MB)
      </p>

      {/* Error message */}
      {error && (
        <p className="text-sm text-[var(--color-error)] text-center">{error}</p>
      )}

      {/* Preview confirmation buttons */}
      {previewUrl && !isLoading && (
        <div className="flex gap-2">
          <Button
            variant="primary"
            size="sm"
            onClick={handleConfirmUpload}
            leftIcon={<Upload className="w-4 h-4" />}
          >
            Upload
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCancelPreview}
            leftIcon={<X className="w-4 h-4" />}
          >
            Cancel
          </Button>
        </div>
      )}

      {/* Remove button (only show if there's a current avatar and not previewing) */}
      {currentUrl && !previewUrl && onRemove && (
        <Button
          variant="ghost"
          size="sm"
          onClick={handleRemove}
          leftIcon={<Trash2 className="w-4 h-4" />}
          className="text-[var(--color-error)] hover:text-[var(--color-error-dark)] hover:bg-[var(--color-error)]/10"
        >
          Remove
        </Button>
      )}
    </div>
  );
}

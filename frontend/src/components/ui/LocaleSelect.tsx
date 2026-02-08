import { useState, useRef, useEffect, useId, useMemo } from 'react';
import { ChevronDown, Search, Check } from 'lucide-react';

interface LocaleOption {
  value: string;
  label: string;
  native: string;
  flag: string;
}

interface LocaleSelectProps {
  value: string;
  onChange: (locale: string) => void;
  className?: string;
  label?: string;
  error?: string;
  placeholder?: string;
}

const LOCALES: LocaleOption[] = [
  { value: 'en-US', label: 'English (US)', native: 'English', flag: '🇺🇸' },
  { value: 'en-GB', label: 'English (UK)', native: 'English', flag: '🇬🇧' },
  { value: 'es-ES', label: 'Spanish (Spain)', native: 'Español', flag: '🇪🇸' },
  { value: 'es-MX', label: 'Spanish (Mexico)', native: 'Español', flag: '🇲🇽' },
  { value: 'fr-FR', label: 'French', native: 'Français', flag: '🇫🇷' },
  { value: 'de-DE', label: 'German', native: 'Deutsch', flag: '🇩🇪' },
  { value: 'it-IT', label: 'Italian', native: 'Italiano', flag: '🇮🇹' },
  { value: 'pt-BR', label: 'Portuguese (Brazil)', native: 'Português', flag: '🇧🇷' },
  { value: 'pt-PT', label: 'Portuguese (Portugal)', native: 'Português', flag: '🇵🇹' },
  { value: 'nl-NL', label: 'Dutch', native: 'Nederlands', flag: '🇳🇱' },
  { value: 'ru-RU', label: 'Russian', native: 'Русский', flag: '🇷🇺' },
  { value: 'ja-JP', label: 'Japanese', native: '日本語', flag: '🇯🇵' },
  { value: 'ko-KR', label: 'Korean', native: '한국어', flag: '🇰🇷' },
  { value: 'zh-CN', label: 'Chinese (Simplified)', native: '简体中文', flag: '🇨🇳' },
  { value: 'zh-TW', label: 'Chinese (Traditional)', native: '繁體中文', flag: '🇹🇼' },
  { value: 'ar-SA', label: 'Arabic', native: 'العربية', flag: '🇸🇦' },
  { value: 'hi-IN', label: 'Hindi', native: 'हिन्दी', flag: '🇮🇳' },
  { value: 'th-TH', label: 'Thai', native: 'ไทย', flag: '🇹🇭' },
  { value: 'vi-VN', label: 'Vietnamese', native: 'Tiếng Việt', flag: '🇻🇳' },
  { value: 'pl-PL', label: 'Polish', native: 'Polski', flag: '🇵🇱' },
  { value: 'tr-TR', label: 'Turkish', native: 'Türkçe', flag: '🇹🇷' },
  { value: 'sv-SE', label: 'Swedish', native: 'Svenska', flag: '🇸🇪' },
  { value: 'da-DK', label: 'Danish', native: 'Dansk', flag: '🇩🇰' },
  { value: 'fi-FI', label: 'Finnish', native: 'Suomi', flag: '🇫🇮' },
  { value: 'no-NO', label: 'Norwegian', native: 'Norsk', flag: '🇳🇴' },
  { value: 'cs-CZ', label: 'Czech', native: 'Čeština', flag: '🇨🇿' },
  { value: 'el-GR', label: 'Greek', native: 'Ελληνικά', flag: '🇬🇷' },
  { value: 'he-IL', label: 'Hebrew', native: 'עברית', flag: '🇮🇱' },
  { value: 'id-ID', label: 'Indonesian', native: 'Bahasa Indonesia', flag: '🇮🇩' },
  { value: 'ms-MY', label: 'Malay', native: 'Bahasa Melayu', flag: '🇲🇾' },
  { value: 'uk-UA', label: 'Ukrainian', native: 'Українська', flag: '🇺🇦' },
  { value: 'ro-RO', label: 'Romanian', native: 'Română', flag: '🇷🇴' },
  { value: 'hu-HU', label: 'Hungarian', native: 'Magyar', flag: '🇭🇺' },
];

export function LocaleSelect({
  value,
  onChange,
  className = '',
  label,
  error,
  placeholder = 'Select language...',
}: LocaleSelectProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const generatedId = useId();

  const selectedLocale = LOCALES.find((locale) => locale.value === value);

  const filteredLocales = useMemo(() => {
    if (!searchQuery.trim()) return LOCALES;
    const query = searchQuery.toLowerCase();
    return LOCALES.filter(
      (locale) =>
        locale.label.toLowerCase().includes(query) ||
        locale.native.toLowerCase().includes(query) ||
        locale.value.toLowerCase().includes(query)
    );
  }, [searchQuery]);

  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearchQuery('');
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false);
        setSearchQuery('');
      }
    }

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isOpen]);

  const handleSelect = (localeValue: string) => {
    onChange(localeValue);
    setIsOpen(false);
    setSearchQuery('');
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      if (!isOpen) {
        event.preventDefault();
        setIsOpen(true);
      }
    }
  };

  return (
    <div className={`w-full ${className}`} ref={containerRef}>
      {label && (
        <label
          htmlFor={generatedId}
          className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1.5"
        >
          {label}
        </label>
      )}
      <div className="relative">
        <button
          type="button"
          id={generatedId}
          onClick={() => setIsOpen(!isOpen)}
          onKeyDown={handleKeyDown}
          className={`
            w-full px-4 py-2.5 rounded-lg
            bg-white border border-[var(--color-border)]
            text-[var(--color-text-primary)]
            transition-all duration-200
            focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/20 focus:border-[var(--color-info)]
            disabled:bg-[var(--color-border-light)] disabled:opacity-60 disabled:cursor-not-allowed
            cursor-pointer text-left flex items-center justify-between
            ${error ? 'border-[var(--color-error)] focus:ring-[var(--color-error)]/20 focus:border-[var(--color-error)]' : ''}
          `}
          aria-haspopup="listbox"
          aria-expanded={isOpen}
        >
          {selectedLocale ? (
            <span className="flex items-center gap-2 truncate">
              <span className="text-lg" role="img" aria-label={selectedLocale.label}>
                {selectedLocale.flag}
              </span>
              <span className="font-medium">{selectedLocale.native}</span>
              <span className="text-[var(--color-text-muted)]">({selectedLocale.label})</span>
            </span>
          ) : (
            <span className="text-[var(--color-text-muted)]">{placeholder}</span>
          )}
          <ChevronDown
            size={18}
            className={`text-[var(--color-text-muted)] transition-transform duration-200 ${
              isOpen ? 'rotate-180' : ''
            }`}
          />
        </button>

        {isOpen && (
          <div
            className="absolute z-50 w-full mt-1 bg-white border border-[var(--color-border)] rounded-lg shadow-lg overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200"
            role="listbox"
          >
            <div className="p-2 border-b border-[var(--color-border)]">
              <div className="relative">
                <Search
                  size={16}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]"
                />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search languages..."
                  className="w-full pl-9 pr-3 py-2 text-sm rounded-md
                    bg-[var(--color-border-light)] border-none
                    text-[var(--color-text-primary)]
                    placeholder-[var(--color-text-muted)]
                    focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/20"
                />
              </div>
            </div>

            <ul
              ref={listRef}
              className="max-h-60 overflow-y-auto py-1"
              role="listbox"
            >
              {filteredLocales.length === 0 ? (
                <li className="px-4 py-3 text-sm text-[var(--color-text-muted)] text-center">
                  No languages found
                </li>
              ) : (
                filteredLocales.map((locale) => (
                  <li
                    key={locale.value}
                    role="option"
                    aria-selected={value === locale.value}
                    onClick={() => handleSelect(locale.value)}
                    className={`
                      px-4 py-2.5 cursor-pointer flex items-center justify-between
                      transition-colors duration-150
                      ${value === locale.value
                        ? 'bg-[var(--color-info)]/10 text-[var(--color-info)]'
                        : 'hover:bg-[var(--color-border-light)]'
                      }
                    `}
                  >
                    <span className="flex items-center gap-3">
                      <span className="text-lg" role="img" aria-label={locale.label}>
                        {locale.flag}
                      </span>
                      <span className="flex flex-col">
                        <span className="font-medium text-sm">{locale.native}</span>
                        <span className="text-xs text-[var(--color-text-muted)]">
                          {locale.label}
                        </span>
                      </span>
                    </span>
                    {value === locale.value && (
                      <Check size={16} className="text-[var(--color-info)]" />
                    )}
                  </li>
                ))
              )}
            </ul>
          </div>
        )}
      </div>
      {error && (
        <p className="mt-1.5 text-sm text-[var(--color-error)] animate-in fade-in slide-in-from-top-1">
          {error}
        </p>
      )}
    </div>
  );
}

LocaleSelect.displayName = 'LocaleSelect';

/* eslint-disable react-refresh/only-export-components */
import { useState, useEffect, useMemo, useRef, useId } from 'react';
import { ChevronDown, Search, MapPin, Clock } from 'lucide-react';

interface TimezoneSelectProps {
  value: string;
  onChange: (timezone: string) => void;
  label?: string;
  error?: string;
  helperText?: string;
  className?: string;
  disabled?: boolean;
}

interface TimezoneOption {
  value: string;
  label: string;
}

interface TimezoneRegion {
  region: string;
  zones: TimezoneOption[];
}

const TIMEZONES: TimezoneRegion[] = [
  {
    region: 'Americas',
    zones: [
      { value: 'America/New_York', label: 'Eastern Time (New York)' },
      { value: 'America/Chicago', label: 'Central Time (Chicago)' },
      { value: 'America/Denver', label: 'Mountain Time (Denver)' },
      { value: 'America/Los_Angeles', label: 'Pacific Time (Los Angeles)' },
      { value: 'America/Anchorage', label: 'Alaska Time' },
      { value: 'America/Honolulu', label: 'Hawaii Time' },
      { value: 'America/Phoenix', label: 'Arizona (No DST)' },
      { value: 'America/Toronto', label: 'Toronto' },
      { value: 'America/Vancouver', label: 'Vancouver' },
      { value: 'America/Montreal', label: 'Montreal' },
      { value: 'America/Edmonton', label: 'Edmonton' },
      { value: 'America/Winnipeg', label: 'Winnipeg' },
      { value: 'America/Mexico_City', label: 'Mexico City' },
      { value: 'America/Tijuana', label: 'Tijuana' },
      { value: 'America/Bogota', label: 'Bogotá' },
      { value: 'America/Lima', label: 'Lima' },
      { value: 'America/Santiago', label: 'Santiago' },
      { value: 'America/Sao_Paulo', label: 'São Paulo' },
      { value: 'America/Buenos_Aires', label: 'Buenos Aires' },
      { value: 'America/Caracas', label: 'Caracas' },
    ],
  },
  {
    region: 'Europe',
    zones: [
      { value: 'Europe/London', label: 'London (GMT/BST)' },
      { value: 'Europe/Dublin', label: 'Dublin' },
      { value: 'Europe/Paris', label: 'Paris (CET)' },
      { value: 'Europe/Berlin', label: 'Berlin (CET)' },
      { value: 'Europe/Madrid', label: 'Madrid' },
      { value: 'Europe/Rome', label: 'Rome' },
      { value: 'Europe/Amsterdam', label: 'Amsterdam' },
      { value: 'Europe/Brussels', label: 'Brussels' },
      { value: 'Europe/Vienna', label: 'Vienna' },
      { value: 'Europe/Zurich', label: 'Zurich' },
      { value: 'Europe/Stockholm', label: 'Stockholm' },
      { value: 'Europe/Oslo', label: 'Oslo' },
      { value: 'Europe/Copenhagen', label: 'Copenhagen' },
      { value: 'Europe/Helsinki', label: 'Helsinki' },
      { value: 'Europe/Warsaw', label: 'Warsaw' },
      { value: 'Europe/Prague', label: 'Prague' },
      { value: 'Europe/Athens', label: 'Athens' },
      { value: 'Europe/Bucharest', label: 'Bucharest' },
      { value: 'Europe/Moscow', label: 'Moscow' },
      { value: 'Europe/Istanbul', label: 'Istanbul' },
      { value: 'Europe/Kiev', label: 'Kyiv' },
    ],
  },
  {
    region: 'Asia',
    zones: [
      { value: 'Asia/Dubai', label: 'Dubai (GST)' },
      { value: 'Asia/Riyadh', label: 'Riyadh' },
      { value: 'Asia/Tehran', label: 'Tehran' },
      { value: 'Asia/Karachi', label: 'Karachi' },
      { value: 'Asia/Kolkata', label: 'India (IST)' },
      { value: 'Asia/Dhaka', label: 'Dhaka' },
      { value: 'Asia/Bangkok', label: 'Bangkok' },
      { value: 'Asia/Ho_Chi_Minh', label: 'Ho Chi Minh City' },
      { value: 'Asia/Jakarta', label: 'Jakarta' },
      { value: 'Asia/Singapore', label: 'Singapore' },
      { value: 'Asia/Kuala_Lumpur', label: 'Kuala Lumpur' },
      { value: 'Asia/Manila', label: 'Manila' },
      { value: 'Asia/Hong_Kong', label: 'Hong Kong' },
      { value: 'Asia/Shanghai', label: 'Shanghai (CST)' },
      { value: 'Asia/Taipei', label: 'Taipei' },
      { value: 'Asia/Seoul', label: 'Seoul (KST)' },
      { value: 'Asia/Tokyo', label: 'Tokyo (JST)' },
    ],
  },
  {
    region: 'Pacific',
    zones: [
      { value: 'Pacific/Auckland', label: 'Auckland (NZST)' },
      { value: 'Pacific/Fiji', label: 'Fiji' },
      { value: 'Pacific/Guam', label: 'Guam' },
      { value: 'Pacific/Port_Moresby', label: 'Port Moresby' },
      { value: 'Pacific/Noumea', label: 'Noumea' },
      { value: 'Pacific/Tahiti', label: 'Tahiti' },
      { value: 'Pacific/Samoa', label: 'Samoa' },
    ],
  },
  {
    region: 'Africa',
    zones: [
      { value: 'Africa/Cairo', label: 'Cairo' },
      { value: 'Africa/Casablanca', label: 'Casablanca' },
      { value: 'Africa/Lagos', label: 'Lagos' },
      { value: 'Africa/Nairobi', label: 'Nairobi' },
      { value: 'Africa/Johannesburg', label: 'Johannesburg' },
      { value: 'Africa/Addis_Ababa', label: 'Addis Ababa' },
      { value: 'Africa/Algiers', label: 'Algiers' },
      { value: 'Africa/Tunis', label: 'Tunis' },
    ],
  },
  {
    region: 'Australia',
    zones: [
      { value: 'Australia/Sydney', label: 'Sydney (AEST)' },
      { value: 'Australia/Melbourne', label: 'Melbourne' },
      { value: 'Australia/Brisbane', label: 'Brisbane' },
      { value: 'Australia/Perth', label: 'Perth (AWST)' },
      { value: 'Australia/Adelaide', label: 'Adelaide' },
      { value: 'Australia/Darwin', label: 'Darwin' },
      { value: 'Australia/Hobart', label: 'Hobart' },
    ],
  },
  {
    region: 'Other',
    zones: [
      { value: 'UTC', label: 'UTC (Coordinated Universal Time)' },
      { value: 'Atlantic/Reykjavik', label: 'Reykjavik (Iceland)' },
      { value: 'Indian/Maldives', label: 'Maldives' },
      { value: 'Indian/Mauritius', label: 'Mauritius' },
    ],
  },
];

function formatTimeInTimezone(timezone: string): string {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
    }).format(new Date());
  } catch {
    return '';
  }
}

function getTimezoneOffset(timezone: string): string {
  try {
    const now = new Date();
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      timeZoneName: 'shortOffset',
    });
    const parts = formatter.formatToParts(now);
    const offsetPart = parts.find((p) => p.type === 'timeZoneName');
    return offsetPart?.value || '';
  } catch {
    return '';
  }
}

function detectUserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return 'UTC';
  }
}

function findTimezoneLabel(value: string): string {
  for (const region of TIMEZONES) {
    const zone = region.zones.find((z) => z.value === value);
    if (zone) return zone.label;
  }
  return value;
}

export const TimezoneSelect = ({
  value,
  onChange,
  label,
  error,
  helperText,
  className = '',
  disabled = false,
}: TimezoneSelectProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentTime, setCurrentTime] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const generatedId = useId();

  // Update current time display
  useEffect(() => {
    if (value) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Sync time display with timezone value
      setCurrentTime(formatTimeInTimezone(value));
      const interval = setInterval(() => {
        setCurrentTime(formatTimeInTimezone(value));
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [value]);

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearchQuery('');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Focus search input when dropdown opens
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen]);

  // Filter timezones based on search
  const filteredTimezones = useMemo(() => {
    if (!searchQuery.trim()) return TIMEZONES;

    const query = searchQuery.toLowerCase();
    return TIMEZONES.map((region) => ({
      ...region,
      zones: region.zones.filter(
        (zone) =>
          zone.label.toLowerCase().includes(query) ||
          zone.value.toLowerCase().includes(query)
      ),
    })).filter((region) => region.zones.length > 0);
  }, [searchQuery]);

  const handleDetectTimezone = () => {
    const detected = detectUserTimezone();
    onChange(detected);
    setIsOpen(false);
    setSearchQuery('');
  };

  const handleSelectTimezone = (tz: string) => {
    onChange(tz);
    setIsOpen(false);
    setSearchQuery('');
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setIsOpen(false);
      setSearchQuery('');
    }
  };

  const selectedLabel = value ? findTimezoneLabel(value) : 'Select timezone...';
  const offset = value ? getTimezoneOffset(value) : '';

  return (
    <div className={`w-full ${className}`} ref={containerRef}>
      {label && (
        <label
          htmlFor={generatedId}
          className="block text-sm font-medium text-[var(--color-text-secondary)] mb-1.5 transition-colors"
        >
          {label}
        </label>
      )}

      {/* Selected Value Display */}
      <button
        type="button"
        id={generatedId}
        disabled={disabled}
        onClick={() => !disabled && setIsOpen(!isOpen)}
        className={`
          w-full px-4 py-2.5 rounded-lg text-left
          bg-white border border-[var(--color-border)]
          text-[var(--color-text-primary)]
          transition-all duration-200
          focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/20 focus:border-[var(--color-info)]
          disabled:bg-[var(--color-border-light)] disabled:opacity-60 disabled:cursor-not-allowed
          ${isOpen ? 'ring-2 ring-[var(--color-info)]/20 border-[var(--color-info)]' : ''}
          ${error ? 'border-[var(--color-error)] focus:ring-[var(--color-error)]/20 focus:border-[var(--color-error)]' : ''}
        `}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <Clock size={16} className="text-[var(--color-text-muted)] flex-shrink-0" />
            <span className={`truncate ${!value ? 'text-[var(--color-text-muted)]' : ''}`}>
              {selectedLabel}
            </span>
            {offset && (
              <span className="text-xs text-[var(--color-text-muted)] flex-shrink-0">
                ({offset})
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {currentTime && (
              <span className="text-sm font-medium text-[var(--color-info)]">
                {currentTime}
              </span>
            )}
            <ChevronDown
              size={18}
              className={`text-[var(--color-text-muted)] transition-transform ${isOpen ? 'rotate-180' : ''}`}
            />
          </div>
        </div>
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div
          className="absolute z-50 mt-1 w-full max-w-md bg-white border border-[var(--color-border)] rounded-lg shadow-lg overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200"
          style={{ maxHeight: '400px' }}
          onKeyDown={handleKeyDown}
        >
          {/* Search Input */}
          <div className="p-3 border-b border-[var(--color-border)] sticky top-0 bg-white">
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
                placeholder="Search timezones..."
                className="w-full pl-9 pr-4 py-2 rounded-md border border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--color-info)]/20 focus:border-[var(--color-info)]"
              />
            </div>

            {/* Detect Timezone Button */}
            <button
              type="button"
              onClick={handleDetectTimezone}
              className="mt-2 w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium text-[var(--color-info)] bg-[var(--color-info)]/10 hover:bg-[var(--color-info)]/20 transition-colors"
            >
              <MapPin size={14} />
              Detect my timezone
            </button>
          </div>

          {/* Timezone List */}
          <div className="overflow-y-auto" style={{ maxHeight: '280px' }}>
            {filteredTimezones.length === 0 ? (
              <div className="p-4 text-center text-[var(--color-text-muted)] text-sm">
                No timezones found
              </div>
            ) : (
              filteredTimezones.map((region) => (
                <div key={region.region}>
                  <div className="px-3 py-2 text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wider bg-[var(--color-bg-secondary)] sticky top-0">
                    {region.region}
                  </div>
                  {region.zones.map((zone) => {
                    const zoneTime = formatTimeInTimezone(zone.value);
                    const zoneOffset = getTimezoneOffset(zone.value);
                    const isSelected = value === zone.value;

                    return (
                      <button
                        key={zone.value}
                        type="button"
                        onClick={() => handleSelectTimezone(zone.value)}
                        className={`
                          w-full px-4 py-2.5 text-left flex items-center justify-between gap-2
                          hover:bg-[var(--color-bg-secondary)] transition-colors
                          ${isSelected ? 'bg-[var(--color-info)]/10 text-[var(--color-info)]' : 'text-[var(--color-text-primary)]'}
                        `}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="truncate">{zone.label}</span>
                            <span className="text-xs text-[var(--color-text-muted)]">
                              {zoneOffset}
                            </span>
                          </div>
                          <div className="text-xs text-[var(--color-text-muted)]">
                            {zone.value}
                          </div>
                        </div>
                        <span className="text-sm text-[var(--color-text-muted)] flex-shrink-0">
                          {zoneTime}
                        </span>
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>
        </div>
      )}

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
};

TimezoneSelect.displayName = 'TimezoneSelect';

export { detectUserTimezone };

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { usePreferences, useUpdatePreferences } from '../../hooks/usePreferences';
import { Palette, Type, Eye, Zap, Keyboard, Check } from 'lucide-react';
import { useToast } from '../ui/Toast';
import type { UpdatePreferencesRequest } from '../../types';

const ACCENT_COLORS = [
  { name: 'Blue', value: '#3b82f6' },
  { name: 'Green', value: '#22c55e' },
  { name: 'Purple', value: '#a855f7' },
  { name: 'Red', value: '#ef4444' },
  { name: 'Orange', value: '#f97316' },
  { name: 'Pink', value: '#ec4899' },
  { name: 'Teal', value: '#14b8a6' },
  { name: 'Gray', value: '#6b7280' },
];

const FONT_SIZES = [
  { label: 'Small', value: 'small' as const, preview: '14px' },
  { label: 'Medium', value: 'medium' as const, preview: '16px' },
  { label: 'Large', value: 'large' as const, preview: '18px' },
];

export function AppearanceSettingsCard() {
  const { data: preferences, isLoading } = usePreferences();
  const updatePreferences = useUpdatePreferences();
  const { showToast } = useToast();
  const [customColor, setCustomColor] = useState('');

  const handleUpdatePreference = async (update: UpdatePreferencesRequest) => {
    try {
      await updatePreferences.mutateAsync(update);
      showToast({
        title: 'Settings Updated',
        message: 'Your preference has been saved.',
        type: 'success',
      });
    } catch {
      showToast({
        title: 'Error',
        message: 'Failed to update preference.',
        type: 'error',
      });
    }
  };

  const handleAccentColorSelect = (color: string) => {
    handleUpdatePreference({ accent_color: color });
  };

  const handleCustomColorSubmit = () => {
    const hexRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;
    if (hexRegex.test(customColor)) {
      handleAccentColorSelect(customColor);
      setCustomColor('');
    } else {
      showToast({
        title: 'Invalid Color',
        message: 'Please enter a valid hex color (e.g., #ff5500)',
        type: 'error',
      });
    }
  };

  const isColorSelected = (color: string) => {
    return preferences?.accent_color?.toLowerCase() === color.toLowerCase();
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Palette size={20} />
            Appearance
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-4">
            <div className="h-20 bg-[var(--color-border)] rounded-lg" />
            <div className="h-16 bg-[var(--color-border)] rounded-lg" />
            <div className="h-12 bg-[var(--color-border)] rounded-lg" />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Palette size={20} />
          Appearance
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Accent Color Picker */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Palette size={16} className="text-[var(--color-text-secondary)]" />
            <label className="text-sm font-medium text-[var(--color-text-primary)]">
              Accent Color
            </label>
          </div>
          <div className="flex flex-wrap gap-3 mb-3">
            {ACCENT_COLORS.map((color) => (
              <button
                key={color.value}
                type="button"
                onClick={() => handleAccentColorSelect(color.value)}
                className={`
                  w-10 h-10 rounded-full border-2 transition-all duration-200
                  flex items-center justify-center
                  hover:scale-110 focus:outline-none focus:ring-2 focus:ring-offset-2
                  ${isColorSelected(color.value)
                    ? 'border-[var(--color-text-primary)] ring-2 ring-offset-2 ring-[var(--color-text-secondary)]'
                    : 'border-transparent'
                  }
                `}
                style={{ backgroundColor: color.value }}
                title={color.name}
                aria-label={`Select ${color.name} accent color`}
              >
                {isColorSelected(color.value) && (
                  <Check size={18} className="text-white drop-shadow-md" />
                )}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="text"
              value={customColor}
              onChange={(e) => setCustomColor(e.target.value)}
              placeholder="#custom"
              className="
                flex-1 px-3 py-2 text-sm rounded-lg
                bg-[var(--color-surface)] border border-[var(--color-border)]
                text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)]
                focus:outline-none focus:ring-2 focus:ring-[var(--color-secondary)]
              "
            />
            <button
              type="button"
              onClick={handleCustomColorSubmit}
              disabled={!customColor}
              className="
                px-4 py-2 text-sm font-medium rounded-lg
                bg-[var(--color-secondary)] text-white
                hover:opacity-90 transition-opacity
                disabled:opacity-50 disabled:cursor-not-allowed
              "
            >
              Apply
            </button>
          </div>
        </div>

        {/* Font Size Selector */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Type size={16} className="text-[var(--color-text-secondary)]" />
            <label className="text-sm font-medium text-[var(--color-text-primary)]">
              Font Size
            </label>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {FONT_SIZES.map((size) => (
              <button
                key={size.value}
                type="button"
                onClick={() => handleUpdatePreference({ font_size: size.value })}
                className={`
                  p-3 rounded-lg border transition-all duration-200
                  flex flex-col items-center gap-1
                  ${preferences?.font_size === size.value
                    ? 'border-[var(--color-secondary)] bg-[var(--color-secondary)]/10'
                    : 'border-[var(--color-border)] hover:border-[var(--color-text-muted)]'
                  }
                `}
              >
                <span
                  className="font-medium text-[var(--color-text-primary)]"
                  style={{ fontSize: size.preview }}
                >
                  Aa
                </span>
                <span className="text-xs text-[var(--color-text-secondary)]">
                  {size.label}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Toggle Settings */}
        <div className="space-y-4">
          {/* High Contrast Mode */}
          <div className="flex items-center justify-between py-3 border-t border-[var(--color-border)]">
            <div className="flex items-center gap-3">
              <Eye size={18} className="text-[var(--color-text-secondary)]" />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  High Contrast Mode
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Increase contrast for better visibility
                </p>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={preferences?.high_contrast ?? false}
              onClick={() => handleUpdatePreference({ high_contrast: !preferences?.high_contrast })}
              className={`
                relative w-11 h-6 rounded-full transition-colors duration-200
                focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[var(--color-secondary)]
                ${preferences?.high_contrast
                  ? 'bg-[var(--color-secondary)]'
                  : 'bg-[var(--color-border)]'
                }
              `}
            >
              <span
                className={`
                  absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200
                  ${preferences?.high_contrast ? 'translate-x-5' : 'translate-x-0'}
                `}
              />
            </button>
          </div>

          {/* Reduced Motion */}
          <div className="flex items-center justify-between py-3 border-t border-[var(--color-border)]">
            <div className="flex items-center gap-3">
              <Zap size={18} className="text-[var(--color-text-secondary)]" />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Reduced Motion
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Minimize animations and transitions
                </p>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={preferences?.reduced_motion ?? false}
              onClick={() => handleUpdatePreference({ reduced_motion: !preferences?.reduced_motion })}
              className={`
                relative w-11 h-6 rounded-full transition-colors duration-200
                focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[var(--color-secondary)]
                ${preferences?.reduced_motion
                  ? 'bg-[var(--color-secondary)]'
                  : 'bg-[var(--color-border)]'
                }
              `}
            >
              <span
                className={`
                  absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200
                  ${preferences?.reduced_motion ? 'translate-x-5' : 'translate-x-0'}
                `}
              />
            </button>
          </div>

          {/* Keyboard Shortcuts */}
          <div className="flex items-center justify-between py-3 border-t border-[var(--color-border)]">
            <div className="flex items-center gap-3">
              <Keyboard size={18} className="text-[var(--color-text-secondary)]" />
              <div>
                <p className="text-sm font-medium text-[var(--color-text-primary)]">
                  Keyboard Shortcuts
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Enable keyboard navigation shortcuts
                </p>
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={preferences?.keyboard_shortcuts_enabled ?? true}
              onClick={() => handleUpdatePreference({ keyboard_shortcuts_enabled: !preferences?.keyboard_shortcuts_enabled })}
              className={`
                relative w-11 h-6 rounded-full transition-colors duration-200
                focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[var(--color-secondary)]
                ${preferences?.keyboard_shortcuts_enabled
                  ? 'bg-[var(--color-secondary)]'
                  : 'bg-[var(--color-border)]'
                }
              `}
            >
              <span
                className={`
                  absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200
                  ${preferences?.keyboard_shortcuts_enabled ? 'translate-x-5' : 'translate-x-0'}
                `}
              />
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

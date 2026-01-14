import { useEffect } from 'react';

interface KeyboardShortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  callback: () => void;
  description: string;
}

export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[]) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.ctrl ? event.ctrlKey || event.metaKey : !event.ctrlKey && !event.metaKey;
        const shiftMatch = shortcut.shift ? event.shiftKey : !event.shiftKey;
        const altMatch = shortcut.alt ? event.altKey : !event.altKey;
        
        if (
          event.key.toLowerCase() === shortcut.key.toLowerCase() &&
          ctrlMatch &&
          shiftMatch &&
          altMatch
        ) {
          event.preventDefault();
          shortcut.callback();
          break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts]);
}

// Common keyboard shortcuts hook
export function useCommonShortcuts(callbacks: {
  onSearch?: () => void;
  onRefresh?: () => void;
  onCreate?: () => void;
  onSave?: () => void;
  onClose?: () => void;
}) {
  const shortcuts: KeyboardShortcut[] = [];

  if (callbacks.onSearch) {
    shortcuts.push({
      key: 'k',
      ctrl: true,
      callback: callbacks.onSearch,
      description: 'Search',
    });
  }

  if (callbacks.onRefresh) {
    shortcuts.push({
      key: 'r',
      ctrl: true,
      callback: callbacks.onRefresh,
      description: 'Refresh',
    });
  }

  if (callbacks.onCreate) {
    shortcuts.push({
      key: 'n',
      ctrl: true,
      callback: callbacks.onCreate,
      description: 'Create new',
    });
  }

  if (callbacks.onSave) {
    shortcuts.push({
      key: 's',
      ctrl: true,
      callback: callbacks.onSave,
      description: 'Save',
    });
  }

  if (callbacks.onClose) {
    shortcuts.push({
      key: 'Escape',
      callback: callbacks.onClose,
      description: 'Close',
    });
  }

  useKeyboardShortcuts(shortcuts);
}

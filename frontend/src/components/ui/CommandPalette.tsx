import { Command } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Modal } from './Modal';

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  icon?: React.ReactNode;
  shortcut?: string;
  onSelect: () => void;
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  commands: CommandItem[];
}

export function CommandPalette({ isOpen, onClose, commands }: CommandPaletteProps) {
  const [search, setSearch] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const filteredCommands = commands.filter(
    (cmd) =>
      cmd.label.toLowerCase().includes(search.toLowerCase()) ||
      cmd.description?.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [search]);

  useEffect(() => {
    if (!isOpen) {
      setSearch('');
      setSelectedIndex(0);
    }
  }, [isOpen]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % filteredCommands.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % filteredCommands.length);
    } else if (e.key === 'Enter' && filteredCommands[selectedIndex]) {
      e.preventDefault();
      filteredCommands[selectedIndex].onSelect();
      onClose();
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="" size="md">
      <div className="space-y-2">
        <div className="relative">
          <Command size={18} className="absolute left-3 top-3 text-[var(--color-text-muted)]" />
          <input
            type="text"
            placeholder="Type a command or search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={handleKeyDown}
            className="w-full pl-10 pr-4 py-3 bg-[var(--color-primary-dark)] text-[var(--color-text-primary)] rounded-lg border border-[var(--color-border-light)] focus:outline-none focus:border-[var(--color-primary-light)]"
            autoFocus
          />
        </div>

        <div className="max-h-96 overflow-y-auto">
          {filteredCommands.length === 0 ? (
            <div className="py-8 text-center text-[var(--color-text-muted)]">
              No commands found
            </div>
          ) : (
            <div className="space-y-1">
              {filteredCommands.map((command, index) => (
                <button
                  key={command.id}
                  onClick={() => {
                    command.onSelect();
                    onClose();
                  }}
                  className={`
                    w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left
                    transition-colors
                    ${
                      index === selectedIndex
                        ? 'bg-[var(--color-primary-medium)]/30 text-[var(--color-text-primary)]'
                        : 'hover:bg-[var(--color-primary-dark)]/50 text-[var(--color-text-secondary)]'
                    }
                  `}
                  onMouseEnter={() => setSelectedIndex(index)}
                >
                  {command.icon && (
                    <div className="flex-shrink-0">{command.icon}</div>
                  )}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{command.label}</p>
                    {command.description && (
                      <p className="text-xs text-[var(--color-text-muted)] truncate">
                        {command.description}
                      </p>
                    )}
                  </div>
                  {command.shortcut && (
                    <kbd className="px-2 py-1 text-xs bg-[var(--color-primary-dark)] rounded border border-[var(--color-border-light)]">
                      {command.shortcut}
                    </kbd>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}

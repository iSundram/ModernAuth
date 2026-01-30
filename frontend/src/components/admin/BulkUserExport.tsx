import { useState } from 'react';
import { Download, FileJson, FileSpreadsheet } from 'lucide-react';
import { Button, Modal } from '../ui';
import { adminService } from '../../api/services';
import { useToast } from '../ui/Toast';

interface BulkUserExportProps {
  isOpen: boolean;
  onClose: () => void;
}

export function BulkUserExport({ isOpen, onClose }: BulkUserExportProps) {
  const [format, setFormat] = useState<'csv' | 'json'>('csv');
  const [activeOnly, setActiveOnly] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { showToast } = useToast();

  const handleExport = async () => {
    setIsLoading(true);
    try {
      const blob = await adminService.exportUsers(format, activeOnly);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `users_export_${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      showToast({
        title: 'Export Successful',
        message: `Users exported as ${format.toUpperCase()}`,
        type: 'success'
      });
      onClose();
    } catch (err) {
      showToast({
        title: 'Export Failed',
        message: err instanceof Error ? err.message : 'Failed to export users',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Export Users">
      <div className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-3">
            Export Format
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setFormat('csv')}
              className={`p-4 rounded-lg border-2 text-left transition-colors ${
                format === 'csv'
                  ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/5'
                  : 'border-[var(--color-border)] hover:border-[var(--color-border-dark)]'
              }`}
            >
              <FileSpreadsheet className={`w-8 h-8 mb-2 ${
                format === 'csv' ? 'text-[var(--color-primary)]' : 'text-[var(--color-text-muted)]'
              }`} />
              <div className="font-medium text-[var(--color-text-primary)]">CSV</div>
              <div className="text-sm text-[var(--color-text-muted)]">
                Excel compatible spreadsheet
              </div>
            </button>
            <button
              type="button"
              onClick={() => setFormat('json')}
              className={`p-4 rounded-lg border-2 text-left transition-colors ${
                format === 'json'
                  ? 'border-[var(--color-primary)] bg-[var(--color-primary)]/5'
                  : 'border-[var(--color-border)] hover:border-[var(--color-border-dark)]'
              }`}
            >
              <FileJson className={`w-8 h-8 mb-2 ${
                format === 'json' ? 'text-[var(--color-primary)]' : 'text-[var(--color-text-muted)]'
              }`} />
              <div className="font-medium text-[var(--color-text-primary)]">JSON</div>
              <div className="text-sm text-[var(--color-text-muted)]">
                Machine readable format
              </div>
            </button>
          </div>
        </div>

        <div className="p-4 bg-[var(--color-background)] rounded-lg">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(e) => setActiveOnly(e.target.checked)}
              className="rounded border-[var(--color-border)]"
            />
            <span className="text-sm text-[var(--color-text-primary)]">
              Export active users only
            </span>
          </label>
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleExport} isLoading={isLoading} leftIcon={<Download size={18} />}>
            Export
          </Button>
        </div>
      </div>
    </Modal>
  );
}

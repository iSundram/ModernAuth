import { useState, useRef } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle, X } from 'lucide-react';
import { Button, Modal } from '../ui';
import { adminService } from '../../api/services';
import { useToast } from '../ui/Toast';
import type { UserBulkImportResult, BulkUserRecord } from '../../types';
import Papa from 'papaparse';

interface BulkUserImportProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export function BulkUserImport({ isOpen, onClose, onSuccess }: BulkUserImportProps) {
  const [mode, setMode] = useState<'upload' | 'preview' | 'results'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [users, setUsers] = useState<BulkUserRecord[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [validateOnly, setValidateOnly] = useState(true);
  const [skipExisting, setSkipExisting] = useState(true);
  const [sendWelcome, setSendWelcome] = useState(false);
  const [result, setResult] = useState<UserBulkImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { showToast } = useToast();

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    setFile(selectedFile);

    // Parse CSV file using papaparse
    Papa.parse(selectedFile, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        if (results.errors.length > 0) {
          showToast({
            title: 'Error',
            message: `Failed to parse CSV: ${results.errors[0].message}`,
            type: 'error'
          });
          return;
        }

        const parsedUsers: BulkUserRecord[] = (results.data as Record<string, unknown>[]).map((row) => {
          return {
            email: String(row.email || ''),
            first_name: String(row.first_name || ''),
            last_name: String(row.last_name || ''),
            username: String(row.username || ''),
            phone: String(row.phone || ''),
            roles: String(row.roles || ''),
            password: String(row.password || ''),
            active: row.active === 'true' || row.active === '1' || row.active === true,
          };
        }).filter(u => u.email); // Ensure email exists

        setUsers(parsedUsers);
        setMode('preview');
      },
      error: (error) => {
        showToast({
          title: 'Error',
          message: `Failed to read file: ${error.message}`,
          type: 'error'
        });
      }
    });
  };

  const handleImport = async () => {
    if (users.length === 0) return;

    setIsLoading(true);
    try {
      const importResult = await adminService.importUsersJSON({
        users,
        skip_existing: skipExisting,
        validate_only: validateOnly,
        send_welcome: sendWelcome,
      });

      setResult(importResult);
      setMode('results');

      if (!validateOnly && importResult.success_count > 0) {
        showToast({
          title: 'Import Successful',
          message: `${importResult.success_count} users imported`,
          type: 'success'
        });
        onSuccess?.();
      }
    } catch (err) {
      showToast({
        title: 'Import Failed',
        message: err instanceof Error ? err.message : 'Failed to import users',
        type: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setMode('upload');
    setFile(null);
    setUsers([]);
    setResult(null);
    setValidateOnly(true);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClose = () => {
    handleReset();
    onClose();
  };

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="Import Users" size="lg">
      <div className="space-y-4">
        {mode === 'upload' && (
          <>
            <div className="border-2 border-dashed border-[var(--color-border)] rounded-lg p-8 text-center hover:border-[var(--color-primary)] transition-colors">
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                onChange={handleFileChange}
                className="hidden"
                id="csv-upload"
              />
              <label htmlFor="csv-upload" className="cursor-pointer">
                <Upload className="w-12 h-12 mx-auto text-[var(--color-text-muted)] mb-4" />
                <p className="text-[var(--color-text-primary)] font-medium mb-1">
                  Click to upload CSV file
                </p>
                <p className="text-sm text-[var(--color-text-muted)]">
                  CSV with columns: email, first_name, last_name, username, phone, roles, password, active
                </p>
              </label>
            </div>

            <div className="bg-[var(--color-background)] rounded-lg p-4">
              <h4 className="font-medium text-[var(--color-text-primary)] mb-2">CSV Format</h4>
              <pre className="text-xs text-[var(--color-text-muted)] overflow-x-auto">
{`email,first_name,last_name,username,active
john@example.com,John,Doe,johndoe,true
jane@example.com,Jane,Smith,janesmith,true`}
              </pre>
            </div>
          </>
        )}

        {mode === 'preview' && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-[var(--color-text-muted)]" />
                <span className="font-medium">{file?.name}</span>
                <span className="text-sm text-[var(--color-text-muted)]">
                  ({users.length} users)
                </span>
              </div>
              <Button size="sm" variant="ghost" onClick={handleReset}>
                <X size={16} />
              </Button>
            </div>

            <div className="max-h-64 overflow-auto border border-[var(--color-border)] rounded-lg">
              <table className="w-full text-sm">
                <thead className="bg-[var(--color-background)] sticky top-0">
                  <tr>
                    <th className="px-3 py-2 text-left">Email</th>
                    <th className="px-3 py-2 text-left">Name</th>
                    <th className="px-3 py-2 text-left">Username</th>
                    <th className="px-3 py-2 text-left">Active</th>
                  </tr>
                </thead>
                <tbody>
                  {users.slice(0, 10).map((user, idx) => (
                    <tr key={idx} className="border-t border-[var(--color-border)]">
                      <td className="px-3 py-2">{user.email}</td>
                      <td className="px-3 py-2">
                        {[user.first_name, user.last_name].filter(Boolean).join(' ') || '-'}
                      </td>
                      <td className="px-3 py-2">{user.username || '-'}</td>
                      <td className="px-3 py-2">{user.active ? 'Yes' : 'No'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {users.length > 10 && (
                <div className="px-3 py-2 text-sm text-[var(--color-text-muted)] bg-[var(--color-background)]">
                  And {users.length - 10} more...
                </div>
              )}
            </div>

            <div className="space-y-3 p-4 bg-[var(--color-background)] rounded-lg">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={validateOnly}
                  onChange={(e) => setValidateOnly(e.target.checked)}
                  className="rounded border-[var(--color-border)]"
                />
                <span className="text-sm">Validate only (dry run)</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={skipExisting}
                  onChange={(e) => setSkipExisting(e.target.checked)}
                  className="rounded border-[var(--color-border)]"
                />
                <span className="text-sm">Skip existing users</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={sendWelcome}
                  onChange={(e) => setSendWelcome(e.target.checked)}
                  className="rounded border-[var(--color-border)]"
                />
                <span className="text-sm">Send welcome emails</span>
              </label>
            </div>

            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={handleReset}>
                Cancel
              </Button>
              <Button onClick={handleImport} isLoading={isLoading}>
                {validateOnly ? 'Validate' : 'Import Users'}
              </Button>
            </div>
          </>
        )}

        {mode === 'results' && result && (
          <>
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 bg-[var(--color-success)]/10 rounded-lg text-center">
                <CheckCircle className="w-8 h-8 text-[var(--color-success)] mx-auto mb-2" />
                <div className="text-2xl font-bold text-[var(--color-success)]">
                  {result.success_count}
                </div>
                <div className="text-sm text-[var(--color-text-muted)]">Successful</div>
              </div>
              <div className="p-4 bg-[var(--color-warning)]/10 rounded-lg text-center">
                <AlertCircle className="w-8 h-8 text-[var(--color-warning)] mx-auto mb-2" />
                <div className="text-2xl font-bold text-[var(--color-warning)]">
                  {result.skipped_count}
                </div>
                <div className="text-sm text-[var(--color-text-muted)]">Skipped</div>
              </div>
              <div className="p-4 bg-[var(--color-error)]/10 rounded-lg text-center">
                <X className="w-8 h-8 text-[var(--color-error)] mx-auto mb-2" />
                <div className="text-2xl font-bold text-[var(--color-error)]">
                  {result.failure_count}
                </div>
                <div className="text-sm text-[var(--color-text-muted)]">Failed</div>
              </div>
            </div>

            {result.validate_only && (
              <div className="p-3 bg-[var(--color-info)]/10 rounded-lg text-sm text-[var(--color-info)]">
                This was a dry run. No users were actually imported.
              </div>
            )}

            {result.errors && result.errors.length > 0 && (
              <div className="max-h-48 overflow-auto">
                <h4 className="font-medium text-[var(--color-text-primary)] mb-2">Errors</h4>
                <div className="space-y-2">
                  {result.errors.map((error, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-[var(--color-error)]/10 rounded text-sm"
                    >
                      <span className="font-medium">Row {error.row}</span>
                      {error.email && <span> ({error.email})</span>}: {error.message}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2">
              {result.validate_only && result.success_count > 0 && (
                <Button onClick={() => { setValidateOnly(false); setMode('preview'); }}>
                  Proceed with Import
                </Button>
              )}
              <Button variant="outline" onClick={handleClose}>
                Close
              </Button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

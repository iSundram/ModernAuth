import { useState, useEffect } from 'react';
import {
  Mail,
  Search,
  Ban,
  Trash2,
  Plus,
  AlertCircle,
  XCircle,
} from 'lucide-react';
import { Button, Input, Card, CardContent, CardHeader, Modal, useToast } from '../../components/ui';
import { emailDeliverabilityService } from '../../api/services';
import type { EmailBounce, EmailSuppression } from '../../types';

type TabType = 'bounces' | 'suppressions';

export function AdminEmailDeliverabilityPage() {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<TabType>('bounces');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Data states
  const [bounces, setBounces] = useState<EmailBounce[]>([]);
  const [bouncesTotal, setBouncesTotal] = useState(0);
  const [suppressions, setSuppressions] = useState<EmailSuppression[]>([]);
  const [suppressionsTotal, setSuppressionsTotal] = useState(0);

  // Modal states
  const [isAddSuppressionModalOpen, setIsAddSuppressionModalOpen] = useState(false);
  const [isRemoveSuppressionModalOpen, setIsRemoveSuppressionModalOpen] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState('');
  const [newSuppressionEmail, setNewSuppressionEmail] = useState('');
  const [newSuppressionReason, setNewSuppressionReason] = useState('');

  const loadBounces = async () => {
    setIsLoading(true);
    try {
      const response = await emailDeliverabilityService.getBounces({
        limit: 100,
        email: searchQuery || undefined,
      });
      setBounces(response.bounces || []);
      setBouncesTotal(response.total || 0);
    } catch (error) {
      console.error('Failed to load bounces:', error);
      showToast({ title: 'Failed to load bounces', type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const loadSuppressions = async () => {
    setIsLoading(true);
    try {
      const response = await emailDeliverabilityService.getSuppressions({
        limit: 100,
        email: searchQuery || undefined,
      });
      setSuppressions(response.suppressions || []);
      setSuppressionsTotal(response.total || 0);
    } catch (error) {
      console.error('Failed to load suppressions:', error);
      showToast({ title: 'Failed to load suppressions', type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'bounces') {
      loadBounces();
    } else {
      loadSuppressions();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, searchQuery]);

  const handleAddSuppression = async () => {
    try {
      await emailDeliverabilityService.addSuppression(newSuppressionEmail, newSuppressionReason || undefined);
      showToast({ title: 'Email added to suppression list', type: 'success' });
      setIsAddSuppressionModalOpen(false);
      setNewSuppressionEmail('');
      setNewSuppressionReason('');
      loadSuppressions();
    } catch (error) {
      console.error('Failed to add suppression:', error);
      showToast({ title: 'Failed to add suppression', type: 'error' });
    }
  };

  const handleRemoveSuppression = async () => {
    try {
      await emailDeliverabilityService.removeSuppression(selectedEmail);
      showToast({ title: 'Email removed from suppression list', type: 'success' });
      setIsRemoveSuppressionModalOpen(false);
      setSelectedEmail('');
      loadSuppressions();
    } catch (error) {
      console.error('Failed to remove suppression:', error);
      showToast({ title: 'Failed to remove suppression', type: 'error' });
    }
  };

  const getBounceTypeColor = (type: string) => {
    switch (type) {
      case 'hard':
        return 'bg-red-500/10 text-red-600 border-red-500/20';
      case 'soft':
        return 'bg-yellow-500/10 text-yellow-600 border-yellow-500/20';
      case 'block':
        return 'bg-orange-500/10 text-orange-600 border-orange-500/20';
      default:
        return 'bg-gray-500/10 text-gray-600 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Email Deliverability</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Monitor email bounces and manage suppression lists
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 gap-4">
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertCircle size={24} className="text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--color-text-primary)]">{bouncesTotal}</p>
                <p className="text-sm text-[var(--color-text-muted)]">Total Bounces</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-orange-500/10 flex items-center justify-center">
                <Ban size={24} className="text-orange-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--color-text-primary)]">{suppressionsTotal}</p>
                <p className="text-sm text-[var(--color-text-muted)]">Suppressed Emails</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-[var(--color-border)]">
        <button
          onClick={() => setActiveTab('bounces')}
          className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'bounces'
              ? 'border-[var(--color-text-primary)] text-[var(--color-text-primary)]'
              : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
          }`}
        >
          Bounces
        </button>
        <button
          onClick={() => setActiveTab('suppressions')}
          className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'suppressions'
              ? 'border-[var(--color-text-primary)] text-[var(--color-text-primary)]'
              : 'border-transparent text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
          }`}
        >
          Suppressions
        </button>
      </div>

      {/* Search and Actions */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--color-text-muted)]" />
          <Input
            type="text"
            placeholder="Search by email..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        {activeTab === 'suppressions' && (
          <Button onClick={() => setIsAddSuppressionModalOpen(true)} leftIcon={<Plus size={16} />}>
            Add Suppression
          </Button>
        )}
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="text-center py-12 text-[var(--color-text-muted)]">Loading...</div>
      ) : activeTab === 'bounces' ? (
        bounces.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Mail className="w-12 h-12 mx-auto mb-4 text-[var(--color-text-muted)]" />
              <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
                No bounces found
              </h3>
              <p className="text-[var(--color-text-secondary)]">
                {searchQuery ? 'Try adjusting your search' : 'Great! No email bounces recorded'}
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <h3 className="font-medium text-[var(--color-text-primary)]">Bounced Emails</h3>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-[var(--color-surface)]">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                        Email
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                        Type
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                        Reason
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                        Date
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-border-light)]">
                    {bounces.map((bounce, index) => (
                      <tr key={index} className="hover:bg-[var(--color-surface-hover)]">
                        <td className="px-4 py-3 text-sm text-[var(--color-text-primary)]">
                          {bounce.email}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium border ${getBounceTypeColor(bounce.type)}`}>
                            {bounce.type}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-[var(--color-text-secondary)] max-w-xs truncate">
                          {bounce.reason || '-'}
                        </td>
                        <td className="px-4 py-3 text-sm text-[var(--color-text-muted)]">
                          {new Date(bounce.bounced_at).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )
      ) : suppressions.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Ban className="w-12 h-12 mx-auto mb-4 text-[var(--color-text-muted)]" />
            <h3 className="text-lg font-medium text-[var(--color-text-primary)] mb-2">
              No suppressions found
            </h3>
            <p className="text-[var(--color-text-secondary)] mb-4">
              {searchQuery ? 'Try adjusting your search' : 'No emails are currently suppressed'}
            </p>
            {!searchQuery && (
              <Button onClick={() => setIsAddSuppressionModalOpen(true)} leftIcon={<Plus size={16} />}>
                Add Suppression
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <h3 className="font-medium text-[var(--color-text-primary)]">Suppressed Emails</h3>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[var(--color-surface)]">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                      Email
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                      Reason
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase">
                      Added
                    </th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-[var(--color-text-muted)] uppercase">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-light)]">
                  {suppressions.map((suppression, index) => (
                    <tr key={index} className="hover:bg-[var(--color-surface-hover)]">
                      <td className="px-4 py-3 text-sm text-[var(--color-text-primary)]">
                        {suppression.email}
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--color-text-secondary)]">
                        {suppression.reason || '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--color-text-muted)]">
                        {new Date(suppression.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => {
                            setSelectedEmail(suppression.email);
                            setIsRemoveSuppressionModalOpen(true);
                          }}
                          className="p-2 rounded-lg hover:bg-[var(--color-error)]/10 text-[var(--color-error)]"
                          title="Remove from suppression list"
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Add Suppression Modal */}
      <Modal isOpen={isAddSuppressionModalOpen} onClose={() => setIsAddSuppressionModalOpen(false)} title="Add Email Suppression">
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Adding an email to the suppression list will prevent any emails from being sent to this address.
          </p>
          <Input
            label="Email Address"
            type="email"
            value={newSuppressionEmail}
            onChange={(e) => setNewSuppressionEmail(e.target.value)}
            placeholder="user@example.com"
          />
          <Input
            label="Reason (optional)"
            value={newSuppressionReason}
            onChange={(e) => setNewSuppressionReason(e.target.value)}
            placeholder="e.g., User requested opt-out"
          />
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsAddSuppressionModalOpen(false)}>Cancel</Button>
            <Button onClick={handleAddSuppression} disabled={!newSuppressionEmail}>Add to Suppression List</Button>
          </div>
        </div>
      </Modal>

      {/* Remove Suppression Modal */}
      <Modal isOpen={isRemoveSuppressionModalOpen} onClose={() => setIsRemoveSuppressionModalOpen(false)} title="Remove Suppression">
        <div className="space-y-4">
          <p className="text-[var(--color-text-secondary)]">
            Are you sure you want to remove <strong>{selectedEmail}</strong> from the suppression list? Emails will be able to be sent to this address again.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="ghost" onClick={() => setIsRemoveSuppressionModalOpen(false)}>Cancel</Button>
            <Button variant="danger" onClick={handleRemoveSuppression}>Remove</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

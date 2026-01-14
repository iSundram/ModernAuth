import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Mail,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
  Clock,
  User,
  Copy,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Badge, Modal, Input, ConfirmDialog } from '../components/ui';
import { invitationService } from '../api/services';
import { useToast } from '../components/ui/Toast';
import type { UserInvitation, CreateInvitationRequest } from '../types';

export function InvitationsPage() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedInvitation, setSelectedInvitation] = useState<UserInvitation | null>(null);
  const [copiedInvitationId, setCopiedInvitationId] = useState<string | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch invitations
  const { data: invitations = [], isLoading } = useQuery({
    queryKey: ['invitations'],
    queryFn: () => invitationService.list(),
  });

  // Create invitation mutation
  const createInvitationMutation = useMutation({
    mutationFn: (data: CreateInvitationRequest) => invitationService.create(data),
    onSuccess: (invitation) => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      showToast({ title: 'Success', message: 'Invitation created successfully', type: 'success' });
      setIsCreateModalOpen(false);
      // Show invitation link/token
      setSelectedInvitation(invitation);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create invitation', type: 'error' });
    },
  });

  // Delete invitation mutation
  const deleteInvitationMutation = useMutation({
    mutationFn: (id: string) => invitationService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      showToast({ title: 'Success', message: 'Invitation deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedInvitation(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete invitation', type: 'error' });
    },
  });

  const handleCopyInvitationLink = (invitationId: string) => {
    // In a real app, this would be the full invitation URL
    const link = `${window.location.origin}/invitations/public/${invitationId}`;
    navigator.clipboard.writeText(link);
    setCopiedInvitationId(invitationId);
    showToast({ title: 'Copied', message: 'Invitation link copied to clipboard', type: 'success' });
    setTimeout(() => setCopiedInvitationId(null), 2000);
  };

  const pendingInvitations = invitations.filter(i => !i.accepted_at && new Date(i.expires_at) > new Date()).length;
  const acceptedInvitations = invitations.filter(i => i.accepted_at).length;
  const expiredInvitations = invitations.filter(i => !i.accepted_at && new Date(i.expires_at) <= new Date()).length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">User Invitations</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Send invitations to users to join your organization.
          </p>
        </div>
        <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
          Send Invitation
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20">
              <Mail size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{invitations.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Invitations</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-yellow-500/10">
              <Clock size={24} className="text-yellow-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{pendingInvitations}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Pending</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{acceptedInvitations}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Accepted</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-red-500/10">
              <XCircle size={24} className="text-red-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{expiredInvitations}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Expired</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Invitations List */}
      <Card>
        <CardHeader>
          <CardTitle>Invitations</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-12">
              <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-[var(--color-text-secondary)]">Loading invitations...</p>
            </div>
          ) : invitations.length === 0 ? (
            <div className="text-center py-12">
              <Mail size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
              <p className="text-[var(--color-text-secondary)] mb-2">No invitations found</p>
              <p className="text-sm text-[var(--color-text-muted)] mb-4">
                Send your first invitation to get started
              </p>
              <Button onClick={() => setIsCreateModalOpen(true)}>
                Send Invitation
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {invitations.map((invitation) => {
                const isExpired = !invitation.accepted_at && new Date(invitation.expires_at) <= new Date();
                const isPending = !invitation.accepted_at && !isExpired;

                return (
                  <div
                    key={invitation.id}
                    className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <div className="flex items-center gap-2">
                            <Mail size={18} className="text-[var(--color-text-muted)]" />
                            <h3 className="font-medium text-[var(--color-text-primary)]">{invitation.email}</h3>
                          </div>
                          {invitation.accepted_at ? (
                            <Badge variant="success" size="sm">
                              <CheckCircle size={12} className="mr-1" />
                              Accepted
                            </Badge>
                          ) : isExpired ? (
                            <Badge variant="error" size="sm">
                              <XCircle size={12} className="mr-1" />
                              Expired
                            </Badge>
                          ) : (
                            <Badge variant="warning" size="sm">
                              <Clock size={12} className="mr-1" />
                              Pending
                            </Badge>
                          )}
                        </div>
                        <div className="space-y-2 text-sm">
                          {(invitation.first_name || invitation.last_name) && (
                            <div className="flex items-center gap-2">
                              <User size={14} className="text-[var(--color-text-muted)]" />
                              <span className="text-[var(--color-text-secondary)]">
                                {invitation.first_name} {invitation.last_name}
                              </span>
                            </div>
                          )}
                          {invitation.message && (
                            <p className="text-[var(--color-text-secondary)] italic">"{invitation.message}"</p>
                          )}
                          {invitation.role_ids && invitation.role_ids.length > 0 && (
                            <div>
                              <p className="text-xs text-[var(--color-text-muted)] mb-1">Roles</p>
                              <div className="flex flex-wrap gap-1">
                                {invitation.role_ids.map((roleId) => (
                                  <Badge key={roleId} variant="default" size="sm">
                                    {roleId.slice(0, 8)}...
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          <div className="flex items-center gap-4 text-xs text-[var(--color-text-muted)]">
                            <div>
                              <span>Expires: </span>
                              <span>{new Date(invitation.expires_at).toLocaleString()}</span>
                            </div>
                            {invitation.accepted_at && (
                              <div>
                                <span>Accepted: </span>
                                <span>{new Date(invitation.accepted_at).toLocaleString()}</span>
                              </div>
                            )}
                            <div>
                              <span>Created: </span>
                              <span>{new Date(invitation.created_at).toLocaleString()}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        {isPending && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleCopyInvitationLink(invitation.id)}
                            title="Copy Invitation Link"
                          >
                            {copiedInvitationId === invitation.id ? (
                              <CheckCircle size={16} className="text-green-500" />
                            ) : (
                              <Copy size={16} />
                            )}
                          </Button>
                        )}
                        {!invitation.accepted_at && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedInvitation(invitation);
                              setIsDeleteModalOpen(true);
                            }}
                            className="text-red-500 hover:text-red-600"
                            title="Delete"
                          >
                            <Trash2 size={16} />
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Invitation Modal */}
      <CreateInvitationModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={(data) => createInvitationMutation.mutate(data)}
        isLoading={createInvitationMutation.isPending}
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedInvitation(null);
        }}
        onConfirm={() => selectedInvitation && deleteInvitationMutation.mutate(selectedInvitation.id)}
        title="Delete Invitation"
        message={`Are you sure you want to delete the invitation for "${selectedInvitation?.email}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  );
}

// Create Invitation Modal Component
function CreateInvitationModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateInvitationRequest) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<CreateInvitationRequest>({
    email: '',
    first_name: '',
    last_name: '',
    role_ids: [],
    group_ids: [],
    message: '',
    expires_at: undefined,
  });
  const [roleIdInput, setRoleIdInput] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.email) {
      return;
    }
    onSubmit(formData);
    setFormData({
      email: '',
      first_name: '',
      last_name: '',
      role_ids: [],
      group_ids: [],
      message: '',
      expires_at: undefined,
    });
    setRoleIdInput('');
  };

  const addRole = () => {
    if (roleIdInput.trim()) {
      setFormData({
        ...formData,
        role_ids: [...(formData.role_ids || []), roleIdInput.trim()],
      });
      setRoleIdInput('');
    }
  };

  const removeRole = (roleId: string) => {
    setFormData({
      ...formData,
      role_ids: formData.role_ids?.filter(id => id !== roleId) || [],
    });
  };

  // Set default expiration to 7 days from now
  const defaultExpiresAt = new Date();
  defaultExpiresAt.setDate(defaultExpiresAt.getDate() + 7);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Send Invitation" size="md">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Email *"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          required
          placeholder="user@example.com"
        />
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="First Name (Optional)"
            value={formData.first_name || ''}
            onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
            placeholder="John"
          />
          <Input
            label="Last Name (Optional)"
            value={formData.last_name || ''}
            onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
            placeholder="Doe"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Role IDs (Optional)
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={roleIdInput}
              onChange={(e) => setRoleIdInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addRole();
                }
              }}
              placeholder="Enter role ID (UUID)"
            />
            <Button type="button" variant="outline" onClick={addRole}>
              Add
            </Button>
          </div>
          {formData.role_ids && formData.role_ids.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {formData.role_ids.map((roleId) => (
                <Badge key={roleId} variant="default" size="sm">
                  {roleId.slice(0, 8)}...
                  <button
                    type="button"
                    onClick={() => removeRole(roleId)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <Input
          label="Message (Optional)"
          value={formData.message || ''}
          onChange={(e) => setFormData({ ...formData, message: e.target.value })}
          placeholder="Personal message to include in invitation"
        />

        <Input
          label="Expires At (Optional)"
          type="datetime-local"
          value={formData.expires_at ? new Date(formData.expires_at).toISOString().slice(0, 16) : ''}
          onChange={(e) => setFormData({ ...formData, expires_at: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
        />

        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Send Invitation
          </Button>
        </div>
      </form>
    </Modal>
  );
}

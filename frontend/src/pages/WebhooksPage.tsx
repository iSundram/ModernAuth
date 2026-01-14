import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Webhook as WebhookIcon,
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, Button, Badge, Modal, Input, ConfirmDialog } from '../components/ui';
import { webhookService } from '../api/services';
import { useToast } from '../components/ui/Toast';
import type { Webhook, CreateWebhookRequest, WebhookDelivery } from '../types';

export function WebhooksPage() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDeliveriesModalOpen, setIsDeliveriesModalOpen] = useState(false);
  const [selectedWebhook, setSelectedWebhook] = useState<Webhook | null>(null);
  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch webhooks
  const { data: webhooks = [], isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => webhookService.list(),
  });

  // Fetch deliveries for selected webhook
  const { data: deliveries = [] } = useQuery({
    queryKey: ['webhook-deliveries', selectedWebhook?.id],
    queryFn: () => selectedWebhook ? webhookService.getDeliveries(selectedWebhook.id) : Promise.resolve([]),
    enabled: !!selectedWebhook && isDeliveriesModalOpen,
  });

  // Create webhook mutation
  const createWebhookMutation = useMutation({
    mutationFn: (data: CreateWebhookRequest) => webhookService.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      showToast({ title: 'Success', message: 'Webhook created successfully', type: 'success' });
      setIsCreateModalOpen(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to create webhook', type: 'error' });
    },
  });

  // Update webhook mutation
  const updateWebhookMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateWebhookRequest> }) => 
      webhookService.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      showToast({ title: 'Success', message: 'Webhook updated successfully', type: 'success' });
      setIsEditModalOpen(false);
      setSelectedWebhook(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update webhook', type: 'error' });
    },
  });

  // Delete webhook mutation
  const deleteWebhookMutation = useMutation({
    mutationFn: (id: string) => webhookService.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      showToast({ title: 'Success', message: 'Webhook deleted successfully', type: 'success' });
      setIsDeleteModalOpen(false);
      setSelectedWebhook(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to delete webhook', type: 'error' });
    },
  });

  const activeWebhooks = webhooks.filter(w => w.is_active).length;
  const totalDeliveries = webhooks.reduce((sum, w) => sum + (w.retry_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Webhooks</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Configure webhook endpoints to receive real-time event notifications.
          </p>
        </div>
        <Button leftIcon={<Plus size={18} />} onClick={() => setIsCreateModalOpen(true)}>
          Create Webhook
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-gradient-to-br from-[#B3B3B3]/30 to-[#D4D4D4]/20">
              <WebhookIcon size={24} className="text-[#D4D4D4]" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{webhooks.length}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Webhooks</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-green-500/10">
              <CheckCircle size={24} className="text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{activeWebhooks}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Active</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-3 rounded-xl bg-blue-500/10">
              <RefreshCw size={24} className="text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-[var(--color-text-primary)]">{totalDeliveries}</p>
              <p className="text-sm text-[var(--color-text-secondary)]">Total Retries</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Webhooks List */}
      <Card>
        <CardHeader>
          <CardTitle>Your Webhooks</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-12">
              <div className="w-8 h-8 border-2 border-[#D4D4D4] border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-[var(--color-text-secondary)]">Loading webhooks...</p>
            </div>
          ) : webhooks.length === 0 ? (
            <div className="text-center py-12">
              <WebhookIcon size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
              <p className="text-[var(--color-text-secondary)] mb-2">No webhooks found</p>
              <p className="text-sm text-[var(--color-text-muted)] mb-4">
                Create your first webhook to receive event notifications
              </p>
              <Button onClick={() => setIsCreateModalOpen(true)}>
                Create Webhook
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {webhooks.map((webhook) => (
                <div
                  key={webhook.id}
                  className="p-4 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-medium text-[var(--color-text-primary)]">{webhook.name}</h3>
                        {webhook.is_active ? (
                          <Badge variant="success" size="sm">
                            <CheckCircle size={12} className="mr-1" />
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="error" size="sm">
                            <XCircle size={12} className="mr-1" />
                            Inactive
                          </Badge>
                        )}
                      </div>
                      {webhook.description && (
                        <p className="text-sm text-[var(--color-text-secondary)] mb-3">{webhook.description}</p>
                      )}
                      <div className="space-y-2">
                        <div>
                          <p className="text-xs text-[var(--color-text-muted)] mb-1">URL</p>
                          <p className="text-sm font-mono text-[var(--color-text-primary)] break-all">{webhook.url}</p>
                        </div>
                        <div className="flex items-center gap-4">
                          {webhook.events && webhook.events.length > 0 && (
                            <div>
                              <p className="text-xs text-[var(--color-text-muted)] mb-1">Events</p>
                              <div className="flex flex-wrap gap-1">
                                {webhook.events.slice(0, 3).map((event) => (
                                  <Badge key={event} variant="default" size="sm">{event}</Badge>
                                ))}
                                {webhook.events.length > 3 && (
                                  <Badge variant="default" size="sm">+{webhook.events.length - 3}</Badge>
                                )}
                              </div>
                            </div>
                          )}
                          <div>
                            <p className="text-xs text-[var(--color-text-muted)] mb-1">Retry Count</p>
                            <p className="text-sm text-[var(--color-text-primary)]">{webhook.retry_count}</p>
                          </div>
                          <div>
                            <p className="text-xs text-[var(--color-text-muted)] mb-1">Timeout</p>
                            <p className="text-sm text-[var(--color-text-primary)]">{webhook.timeout_seconds}s</p>
                          </div>
                        </div>
                        <div className="text-xs text-[var(--color-text-muted)]">
                          Created: {new Date(webhook.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 ml-4">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedWebhook(webhook);
                          setIsDeliveriesModalOpen(true);
                        }}
                        title="View Deliveries"
                      >
                        <Eye size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedWebhook(webhook);
                          setIsEditModalOpen(true);
                        }}
                        title="Edit"
                      >
                        <Edit size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedWebhook(webhook);
                          setIsDeleteModalOpen(true);
                        }}
                        className="text-red-500 hover:text-red-600"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Webhook Modal */}
      <CreateWebhookModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={(data) => createWebhookMutation.mutate(data)}
        isLoading={createWebhookMutation.isPending}
      />

      {/* Edit Webhook Modal */}
      {selectedWebhook && (
        <EditWebhookModal
          isOpen={isEditModalOpen}
          onClose={() => {
            setIsEditModalOpen(false);
            setSelectedWebhook(null);
          }}
          webhook={selectedWebhook}
          onSubmit={(data) => updateWebhookMutation.mutate({ id: selectedWebhook.id, data })}
          isLoading={updateWebhookMutation.isPending}
        />
      )}

      {/* Deliveries Modal */}
      {selectedWebhook && (
        <WebhookDeliveriesModal
          isOpen={isDeliveriesModalOpen}
          onClose={() => {
            setIsDeliveriesModalOpen(false);
            setSelectedWebhook(null);
          }}
          webhook={selectedWebhook}
          deliveries={deliveries}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedWebhook(null);
        }}
        onConfirm={() => selectedWebhook && deleteWebhookMutation.mutate(selectedWebhook.id)}
        title="Delete Webhook"
        message={`Are you sure you want to delete "${selectedWebhook?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  );
}

// Create Webhook Modal Component
function CreateWebhookModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: CreateWebhookRequest) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<CreateWebhookRequest>({
    name: '',
    description: '',
    url: '',
    events: [],
    headers: {},
    retry_count: 3,
    timeout_seconds: 30,
  });
  const [eventInput, setEventInput] = useState('');
  const [headerKey, setHeaderKey] = useState('');
  const [headerValue, setHeaderValue] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.url) {
      return;
    }
    onSubmit(formData);
    setFormData({
      name: '',
      description: '',
      url: '',
      events: [],
      headers: {},
      retry_count: 3,
      timeout_seconds: 30,
    });
    setEventInput('');
    setHeaderKey('');
    setHeaderValue('');
  };

  const addEvent = () => {
    if (eventInput.trim()) {
      setFormData({
        ...formData,
        events: [...(formData.events || []), eventInput.trim()],
      });
      setEventInput('');
    }
  };

  const removeEvent = (event: string) => {
    setFormData({
      ...formData,
      events: formData.events?.filter(e => e !== event) || [],
    });
  };

  const addHeader = () => {
    if (headerKey.trim() && headerValue.trim()) {
      setFormData({
        ...formData,
        headers: {
          ...(formData.headers || {}),
          [headerKey.trim()]: headerValue.trim(),
        },
      });
      setHeaderKey('');
      setHeaderValue('');
    }
  };

  const removeHeader = (key: string) => {
    const newHeaders = { ...(formData.headers || {}) };
    delete newHeaders[key];
    setFormData({
      ...formData,
      headers: newHeaders,
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Webhook" size="lg">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
          placeholder="My Webhook"
        />
        <Input
          label="Description (Optional)"
          value={formData.description || ''}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="What is this webhook for?"
        />
        <Input
          label="URL"
          type="url"
          value={formData.url}
          onChange={(e) => setFormData({ ...formData, url: e.target.value })}
          required
          placeholder="https://example.com/webhook"
        />
        
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Events *
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={eventInput}
              onChange={(e) => setEventInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addEvent();
                }
              }}
              placeholder="user.created, user.updated, etc."
            />
            <Button type="button" variant="outline" onClick={addEvent}>
              Add
            </Button>
          </div>
          {formData.events && formData.events.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {formData.events.map((event) => (
                <Badge key={event} variant="default" size="sm">
                  {event}
                  <button
                    type="button"
                    onClick={() => removeEvent(event)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Custom Headers (Optional)
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={headerKey}
              onChange={(e) => setHeaderKey(e.target.value)}
              placeholder="Header name"
            />
            <Input
              value={headerValue}
              onChange={(e) => setHeaderValue(e.target.value)}
              placeholder="Header value"
            />
            <Button type="button" variant="outline" onClick={addHeader}>
              Add
            </Button>
          </div>
          {formData.headers && Object.keys(formData.headers).length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {Object.entries(formData.headers).map(([key, value]) => (
                <Badge key={key} variant="default" size="sm">
                  {key}: {value as string}
                  <button
                    type="button"
                    onClick={() => removeHeader(key)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Retry Count"
            type="number"
            value={formData.retry_count?.toString() || '3'}
            onChange={(e) => setFormData({ ...formData, retry_count: parseInt(e.target.value) || 3 })}
            min={0}
            max={10}
          />
          <Input
            label="Timeout (seconds)"
            type="number"
            value={formData.timeout_seconds?.toString() || '30'}
            onChange={(e) => setFormData({ ...formData, timeout_seconds: parseInt(e.target.value) || 30 })}
            min={1}
            max={300}
          />
        </div>

        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Create Webhook
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Edit Webhook Modal Component
function EditWebhookModal({
  isOpen,
  onClose,
  webhook,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean;
  onClose: () => void;
  webhook: Webhook;
  onSubmit: (data: Partial<CreateWebhookRequest>) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState<Partial<CreateWebhookRequest>>({
    name: webhook.name,
    description: webhook.description || '',
    url: webhook.url,
    events: webhook.events,
    headers: webhook.headers,
    retry_count: webhook.retry_count,
    timeout_seconds: webhook.timeout_seconds,
  });
  const [eventInput, setEventInput] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const addEvent = () => {
    if (eventInput.trim()) {
      setFormData({
        ...formData,
        events: [...(formData.events || []), eventInput.trim()],
      });
      setEventInput('');
    }
  };

  const removeEvent = (event: string) => {
    setFormData({
      ...formData,
      events: formData.events?.filter(e => e !== event) || [],
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Edit Webhook" size="lg">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name"
          value={formData.name || ''}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
        />
        <Input
          label="Description"
          value={formData.description || ''}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
        <Input
          label="URL"
          type="url"
          value={formData.url || ''}
          onChange={(e) => setFormData({ ...formData, url: e.target.value })}
          required
        />
        
        <div>
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2">
            Events
          </label>
          <div className="flex gap-2 mb-2">
            <Input
              value={eventInput}
              onChange={(e) => setEventInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addEvent();
                }
              }}
              placeholder="Add event"
            />
            <Button type="button" variant="outline" onClick={addEvent}>
              Add
            </Button>
          </div>
          {formData.events && formData.events.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {formData.events.map((event) => (
                <Badge key={event} variant="default" size="sm">
                  {event}
                  <button
                    type="button"
                    onClick={() => removeEvent(event)}
                    className="ml-1 hover:text-red-500"
                  >
                    ×
                  </button>
                </Badge>
              ))}
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Retry Count"
            type="number"
            value={formData.retry_count?.toString() || '3'}
            onChange={(e) => setFormData({ ...formData, retry_count: parseInt(e.target.value) || 3 })}
            min={0}
            max={10}
          />
          <Input
            label="Timeout (seconds)"
            type="number"
            value={formData.timeout_seconds?.toString() || '30'}
            onChange={(e) => setFormData({ ...formData, timeout_seconds: parseInt(e.target.value) || 30 })}
            min={1}
            max={300}
          />
        </div>

        <div className="flex gap-3 pt-4">
          <Button type="button" variant="ghost" onClick={onClose} className="flex-1">
            Cancel
          </Button>
          <Button type="submit" variant="primary" className="flex-1" isLoading={isLoading}>
            Save Changes
          </Button>
        </div>
      </form>
    </Modal>
  );
}

// Webhook Deliveries Modal Component
function WebhookDeliveriesModal({
  isOpen,
  onClose,
  webhook,
  deliveries,
}: {
  isOpen: boolean;
  onClose: () => void;
  webhook: Webhook;
  deliveries: WebhookDelivery[];
}) {
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return <Badge variant="success" size="sm">Success</Badge>;
      case 'failed':
        return <Badge variant="error" size="sm">Failed</Badge>;
      case 'retrying':
        return <Badge variant="warning" size="sm">Retrying</Badge>;
      default:
        return <Badge variant="default" size="sm">{status}</Badge>;
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Webhook Deliveries - ${webhook.name}`} size="lg">
      <div className="space-y-4">
        {deliveries.length === 0 ? (
          <div className="text-center py-8">
            <Clock size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
            <p className="text-[var(--color-text-secondary)]">No deliveries yet</p>
          </div>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {deliveries.map((delivery) => (
              <div
                key={delivery.id}
                className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)]"
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      {getStatusBadge(delivery.status)}
                      <span className="text-sm font-medium text-[var(--color-text-primary)]">
                        {delivery.event_type}
                      </span>
                    </div>
                    <div className="text-xs text-[var(--color-text-muted)] space-y-1">
                      <div>Attempt #{delivery.attempt_number}</div>
                      {delivery.response_status_code && (
                        <div>Status: {delivery.response_status_code}</div>
                      )}
                      {delivery.response_time_ms && (
                        <div>Response Time: {delivery.response_time_ms}ms</div>
                      )}
                      {delivery.created_at && (
                        <div>Created: {new Date(delivery.created_at).toLocaleString()}</div>
                      )}
                    </div>
                  </div>
                </div>
                {delivery.error_message && (
                  <div className="mt-2 p-2 rounded bg-red-500/10 border border-red-500/20">
                    <p className="text-xs text-red-500">{delivery.error_message}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="flex justify-end pt-4">
          <Button variant="primary" onClick={onClose}>Close</Button>
        </div>
      </div>
    </Modal>
  );
}

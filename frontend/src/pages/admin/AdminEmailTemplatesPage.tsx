import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Mail, Edit2, Eye, Save, RotateCcw, 
  FileText, Send, History, AlertCircle, Check,
  Search, Copy, Download,
  Undo, Redo, Smartphone, Monitor
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Input, Modal, LoadingBar, Badge } from '../../components/ui';
import { useToast } from '../../components/ui/Toast';
import { adminService } from '../../api/services';
import type { EmailTemplateSummary, EmailTemplate, EmailTemplateVariables, EmailTemplateVersion } from '../../types';

// Template type labels - used as fallback if backend description is missing
const templateLabels: Record<string, { name: string; description: string; category: string }> = {
  welcome: { name: 'Welcome Email', description: 'Sent when a new user registers', category: 'onboarding' },
  verification: { name: 'Email Verification', description: 'Email verification link', category: 'security' },
  password_reset: { name: 'Password Reset', description: 'Password reset instructions', category: 'security' },
  password_changed: { name: 'Password Changed', description: 'Confirmation of password change', category: 'security' },
  password_expiry: { name: 'Password Expiry', description: 'Warning before password expires', category: 'security' },
  mfa_enabled: { name: 'MFA Enabled', description: 'Confirmation of MFA setup', category: 'security' },
  mfa_disabled: { name: 'MFA Disabled', description: 'Confirmation of MFA removal', category: 'security' },
  mfa_code: { name: 'MFA Code', description: 'Verification code for login', category: 'security' },
  login_alert: { name: 'Login Alert', description: 'New login from unknown device', category: 'security' },
  security_alert: { name: 'Security Alert', description: 'Generic security notifications', category: 'security' },
  invitation: { name: 'Invitation', description: 'User invitation to join', category: 'tenant' },
  session_revoked: { name: 'Session Revoked', description: 'Session revocation notice', category: 'security' },
  magic_link: { name: 'Magic Link', description: 'Passwordless login link', category: 'authentication' },
  account_deactivated: { name: 'Account Deactivated', description: 'Account deactivation notice', category: 'account' },
  email_changed: { name: 'Email Changed', description: 'Email address change confirmation', category: 'account' },
  rate_limit_warning: { name: 'Rate Limit Warning', description: 'Rate limit approaching notification', category: 'system' },
  low_backup_codes: { name: 'Low Backup Codes', description: 'Warning about remaining backup codes', category: 'security' },
};

// Template categories for filtering
const templateCategories = [
  { id: 'all', name: 'All Templates' },
  { id: 'security', name: 'Security' },
  { id: 'authentication', name: 'Authentication' },
  { id: 'account', name: 'Account' },
  { id: 'onboarding', name: 'Onboarding' },
  { id: 'tenant', name: 'Tenant' },
  { id: 'system', name: 'System' },
];

export function AdminEmailTemplatesPage() {
  const [selectedTemplate, setSelectedTemplate] = useState<EmailTemplate | null>(null);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [editMode, setEditMode] = useState(false);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [loadingTemplate, setLoadingTemplate] = useState(false);
  const [editData, setEditData] = useState({
    subject: '',
    html_body: '',
    text_body: '',
  });
  
  // New state for enhanced features
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [previewDevice, setPreviewDevice] = useState<'desktop' | 'mobile'>('desktop');
  const [copiedVariable, setCopiedVariable] = useState<string | null>(null);
  
  // Undo/Redo history
  const [history, setHistory] = useState<Array<typeof editData>>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);

  // New state for test email
  const [testEmailModal, setTestEmailModal] = useState(false);
  const [testEmailRecipient, setTestEmailRecipient] = useState('');
  const [testEmailType, setTestEmailType] = useState('');

  // New state for version history
  const [versionHistoryModal, setVersionHistoryModal] = useState(false);
  const [versionHistoryType, setVersionHistoryType] = useState('');
  const [versions, setVersions] = useState<EmailTemplateVersion[]>([]);
  const [loadingVersions, setLoadingVersions] = useState(false);

  // Validation state
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [isValidating, setIsValidating] = useState(false);

  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch templates list (summaries)
  const { data: templates = [], isLoading } = useQuery<EmailTemplateSummary[]>({
    queryKey: ['email-templates'],
    queryFn: () => adminService.listEmailTemplates(),
  });

  // Fetch variables
  const { data: variables } = useQuery<EmailTemplateVariables>({
    queryKey: ['email-template-variables'],
    queryFn: () => adminService.getEmailTemplateVariables(),
  });

  // Filter templates by search and category
  const filteredTemplates = templates.filter(template => {
    const config = templateLabels[template.type];
    const matchesSearch = searchQuery === '' || 
      (config?.name?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false) ||
      template.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || config?.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Undo/Redo handlers
  const saveToHistory = useCallback((newData: typeof editData) => {
    setHistory(prev => {
      const newHistory = prev.slice(0, historyIndex + 1);
      return [...newHistory, newData];
    });
    setHistoryIndex(prev => prev + 1);
    setEditData(newData);
  }, [historyIndex]);

  const handleUndo = useCallback(() => {
    if (historyIndex > 0) {
      setHistoryIndex(prev => prev - 1);
      setEditData(history[historyIndex - 1]);
    }
  }, [history, historyIndex]);

  const handleRedo = useCallback(() => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(prev => prev + 1);
      setEditData(history[historyIndex + 1]);
    }
  }, [history, historyIndex]);

  // Copy variable to clipboard
  const handleCopyVariable = useCallback((variable: string) => {
    navigator.clipboard.writeText(variable);
    setCopiedVariable(variable);
    setTimeout(() => setCopiedVariable(null), 2000);
    showToast({ title: 'Copied', message: `${variable} copied to clipboard`, type: 'success' });
  }, [showToast]);

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ type, data }: { type: string; data: Partial<EmailTemplate> }) =>
      adminService.updateEmailTemplate(type, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] });
      showToast({ title: 'Success', message: 'Template updated successfully', type: 'success' });
      setEditMode(false);
      setSelectedTemplate(null);
      setValidationErrors([]);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update template', type: 'error' });
    },
  });

  // Reset mutation
  const resetMutation = useMutation({
    mutationFn: (type: string) => adminService.deleteEmailTemplate(type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] });
      showToast({ title: 'Success', message: 'Template reset to default', type: 'success' });
      setSelectedTemplate(null);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to reset template', type: 'error' });
    },
  });

  // Test email mutation
  const testEmailMutation = useMutation({
    mutationFn: ({ type, email }: { type: string; email: string }) =>
      adminService.sendTestEmail(type, email),
    onSuccess: (data) => {
      showToast({ title: 'Success', message: `Test email sent to ${data.recipient}`, type: 'success' });
      setTestEmailModal(false);
      setTestEmailRecipient('');
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to send test email', type: 'error' });
    },
  });

  // Restore version mutation
  const restoreVersionMutation = useMutation({
    mutationFn: ({ type, versionId }: { type: string; versionId: string }) =>
      adminService.restoreEmailTemplateVersion(type, versionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] });
      showToast({ title: 'Success', message: 'Template restored to previous version', type: 'success' });
      setVersionHistoryModal(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to restore version', type: 'error' });
    },
  });

  // Fetch full template for editing
  const handleEdit = async (templateSummary: EmailTemplateSummary) => {
    setLoadingTemplate(true);
    setSelectedType(templateSummary.type);
    setValidationErrors([]);
    setHistory([]);
    setHistoryIndex(-1);
    try {
      const fullTemplate = await adminService.getEmailTemplate(templateSummary.type);
      setSelectedTemplate(fullTemplate);
      setEditData({
        subject: fullTemplate.subject,
        html_body: fullTemplate.html_body,
        text_body: fullTemplate.text_body || '',
      });
      setHistory([{
        subject: fullTemplate.subject,
        html_body: fullTemplate.html_body,
        text_body: fullTemplate.text_body || '',
      }]);
      setHistoryIndex(0);
      setEditMode(true);
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to load template', 
        type: 'error' 
      });
    } finally {
      setLoadingTemplate(false);
    }
  };

  const handleSave = () => {
    if (!selectedTemplate) return;
    saveToHistory(editData);
    updateMutation.mutate({
      type: selectedTemplate.type,
      data: editData,
    });
  };

  const handlePreview = async (templateSummary: EmailTemplateSummary) => {
    try {
      const result = await adminService.previewEmailTemplate(templateSummary.type);
      setPreviewHtml(result.html);
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to preview template', 
        type: 'error' 
      });
    }
  };

  // Validate template before save
  const handleValidate = async () => {
    if (!selectedTemplate) return;
    setIsValidating(true);
    try {
      const result = await adminService.validateEmailTemplate(selectedTemplate.type, {
        subject: editData.subject,
        html_body: editData.html_body,
        text_body: editData.text_body || undefined,
      });
      if (result.valid) {
        setValidationErrors([]);
        showToast({ title: 'Valid', message: 'Template syntax is valid', type: 'success' });
      } else {
        setValidationErrors(result.errors || []);
      }
    } catch (error) {
      showToast({
        title: 'Error',
        message: error instanceof Error ? error.message : 'Validation failed',
        type: 'error'
      });
    } finally {
      setIsValidating(false);
    }
  };

  // Open test email modal
  const handleTestEmail = (templateType: string) => {
    setTestEmailType(templateType);
    setTestEmailRecipient('');
    setTestEmailModal(true);
  };

  // Send test email
  const handleSendTestEmail = () => {
    if (!testEmailRecipient || !testEmailType) return;
    testEmailMutation.mutate({ type: testEmailType, email: testEmailRecipient });
  };

  // Open version history modal
  const handleVersionHistory = async (templateType: string) => {
    setVersionHistoryType(templateType);
    setLoadingVersions(true);
    setVersionHistoryModal(true);
    try {
      const versionList = await adminService.listEmailTemplateVersions(templateType);
      setVersions(versionList);
    } catch (error) {
      showToast({
        title: 'Error',
        message: error instanceof Error ? error.message : 'Failed to load versions',
        type: 'error'
      });
      setVersions([]);
    } finally {
      setLoadingVersions(false);
    }
  };

  // Restore a version
  const handleRestoreVersion = (versionId: string) => {
    if (!versionHistoryType) return;
    restoreVersionMutation.mutate({ type: versionHistoryType, versionId });
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading} message="Loading templates..." />

      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Email Templates</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Customize the email templates sent to your users.
        </p>
      </div>

      {/* Search and Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div className="flex gap-2 flex-wrap">
          {templateCategories.map(cat => (
            <Button
              key={cat.id}
              variant={selectedCategory === cat.id ? 'primary' : 'ghost'}
              size="sm"
              onClick={() => setSelectedCategory(cat.id)}
            >
              {cat.name}
            </Button>
          ))}
        </div>
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" size={16} />
          <Input
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* Template List */}
      {!isLoading && filteredTemplates.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Mail size={48} className="mx-auto text-[var(--color-text-muted)] mb-4" />
            <p className="text-[var(--color-text-secondary)]">No email templates found.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredTemplates.map((template) => {
            const config = templateLabels[template.type] || { 
              name: template.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()), 
              description: template.description || 'Email template',
              category: 'system'
            };
            return (
              <Card key={template.type} className="hover:border-[var(--color-primary)] transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <div className="p-2 rounded-lg bg-[var(--color-primary-dark)]">
                        <Mail size={18} className="text-[#D4D4D4]" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-medium text-[var(--color-text-primary)]">
                            {config.name}
                          </h3>
                          <Badge variant="default" size="sm">{config.category}</Badge>
                          {template.has_custom && (
                            <Badge variant="primary" size="sm">Custom</Badge>
                          )}
                          {!template.is_active && (
                            <Badge variant="warning" size="sm">Inactive</Badge>
                          )}
                        </div>
                        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                          {template.description || config.description}
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-1 flex-wrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handlePreview(template)}
                        title="Preview"
                      >
                        <Eye size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleEdit(template)}
                        isLoading={loadingTemplate && selectedType === template.type}
                        title="Edit"
                      >
                        <Edit2 size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleTestEmail(template.type)}
                        title="Send Test Email"
                      >
                        <Send size={16} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleVersionHistory(template.type)}
                        title="Version History"
                      >
                        <History size={16} />
                      </Button>
                      {template.has_custom && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => resetMutation.mutate(template.type)}
                          title="Reset to default"
                          className="text-yellow-500"
                        >
                          <RotateCcw size={16} />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Available Variables */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText size={18} />
            Available Variables
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-[var(--color-text-secondary)] mb-4">
            Click on any variable to copy it to your clipboard. Use these variables in your templates.
          </p>
          
          {variables && (
            <div className="space-y-6">
              {/* Common Variables */}
              <div>
                <h4 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">Common Variables</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {[
                    { name: 'FullName', description: 'User\'s full name' },
                    { name: 'FirstName', description: 'User\'s first name' },
                    { name: 'LastName', description: 'User\'s last name' },
                    { name: 'Email', description: 'User\'s email address' },
                    { name: 'AppName', description: 'Application name' },
                    { name: 'CurrentYear', description: 'Current year' },
                    { name: 'CurrentDate', description: 'Current date' },
                    { name: 'CurrentTime', description: 'Current time' },
                    { name: 'UnsubscribeURL', description: 'Unsubscribe link' },
                  ].map((variable) => {
                    const varName = `{{.${variable.name}}}`;
                    const isCopied = copiedVariable === varName;
                    return (
                      <div 
                        key={variable.name}
                        onClick={() => handleCopyVariable(varName)}
                        className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <code className="text-sm font-mono text-[var(--color-primary)]">
                            {varName}
                          </code>
                          {isCopied ? (
                            <Check size={14} className="text-green-500" />
                          ) : (
                            <Copy size={14} className="text-[var(--color-text-muted)]" />
                          )}
                        </div>
                        <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                          {variable.description}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* User Variables */}
              <div>
                <h4 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">User Variables</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {variables.user?.map((variable) => {
                    const varName = `{{.${variable.name}}}`;
                    const isCopied = copiedVariable === varName;
                    return (
                      <div 
                        key={variable.name}
                        onClick={() => handleCopyVariable(varName)}
                        className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <code className="text-sm font-mono text-[var(--color-primary)]">
                            {varName}
                          </code>
                          {isCopied ? (
                            <Check size={14} className="text-green-500" />
                          ) : (
                            <Copy size={14} className="text-[var(--color-text-muted)]" />
                          )}
                        </div>
                        <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                          {variable.description}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Branding Variables */}
              <div>
                <h4 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">Branding Variables</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {variables.branding?.map((variable) => {
                    const varName = `{{.${variable.name}}}`;
                    const isCopied = copiedVariable === varName;
                    return (
                      <div 
                        key={variable.name}
                        onClick={() => handleCopyVariable(varName)}
                        className="p-3 rounded-lg bg-[var(--color-surface-hover)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <code className="text-sm font-mono text-[var(--color-primary)]">
                            {varName}
                          </code>
                          {isCopied ? (
                            <Check size={14} className="text-green-500" />
                          ) : (
                            <Copy size={14} className="text-[var(--color-text-muted)]" />
                          )}
                        </div>
                        <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                          {variable.description}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Context Variables */}
              {variables.context && Object.keys(variables.context).length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-[var(--color-text-primary)] mb-2">Context Variables (Template-specific)</h4>
                  <div className="space-y-3">
                    {Object.entries(variables.context).map(([templateType, vars]) => {
                      if (!vars || vars.length === 0) return null;
                      return (
                        <div key={templateType}>
                          <p className="text-xs text-[var(--color-text-muted)] mb-2 capitalize">{templateType.replace(/_/g, ' ')}:</p>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                            {vars.map((variable) => {
                              const varName = `{{.${variable.name}}}`;
                              const isCopied = copiedVariable === varName;
                              return (
                                <div 
                                  key={`${templateType}-${variable.name}`}
                                  onClick={() => handleCopyVariable(varName)}
                                  className="p-2 rounded bg-[var(--color-surface-hover)] border border-[var(--color-border)] cursor-pointer hover:border-[var(--color-primary)] transition-colors"
                                >
                                  <div className="flex items-center justify-between">
                                    <code className="text-xs font-mono text-[var(--color-primary)]">
                                      {varName}
                                    </code>
                                    {isCopied ? (
                                      <Check size={12} className="text-green-500" />
                                    ) : (
                                      <Copy size={12} className="text-[var(--color-text-muted)]" />
                                    )}
                                  </div>
                                  <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
                                    {variable.description}
                                  </p>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Modal */}
      <Modal
        isOpen={editMode && !!selectedTemplate}
        onClose={() => { setEditMode(false); setSelectedTemplate(null); setHistory([]); setHistoryIndex(-1); }}
        title={`Edit Template: ${templateLabels[selectedTemplate?.type || '']?.name || selectedTemplate?.type}`}
        size="xl"
      >
        <div className="space-y-4">
          <Input
            label="Subject"
            value={editData.subject}
            onChange={(e) => saveToHistory({ ...editData, subject: e.target.value })}
            placeholder="Email subject line"
          />

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-[var(--color-text-primary)]">
                HTML Body
              </label>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleUndo}
                  disabled={historyIndex <= 0}
                  title="Undo"
                >
                  <Undo size={14} />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleRedo}
                  disabled={historyIndex >= history.length - 1}
                  title="Redo"
                >
                  <Redo size={14} />
                </Button>
              </div>
            </div>
            <textarea
              value={editData.html_body}
              onChange={(e) => saveToHistory({ ...editData, html_body: e.target.value })}
              className="w-full h-64 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
              placeholder="HTML template content..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
              Plain Text Body (Optional)
            </label>
            <textarea
              value={editData.text_body}
              onChange={(e) => saveToHistory({ ...editData, text_body: e.target.value })}
              className="w-full h-32 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
              placeholder="Plain text fallback..."
            />
          </div>

          {/* Validation Errors */}
          {validationErrors.length > 0 && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <div className="flex items-center gap-2 text-red-400 mb-2">
                <AlertCircle size={16} />
                <span className="font-medium">Template Validation Errors</span>
              </div>
              <ul className="list-disc list-inside text-sm text-red-300 space-y-1">
                {validationErrors.map((error, idx) => (
                  <li key={idx}>{error}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <Button 
              variant="ghost" 
              onClick={() => { setEditMode(false); setSelectedTemplate(null); setHistory([]); setHistoryIndex(-1); }}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="outline" 
              onClick={handleValidate}
              isLoading={isValidating}
            >
              <Check size={16} className="mr-2" />
              Validate
            </Button>
            <Button 
              variant="primary" 
              onClick={handleSave}
              isLoading={updateMutation.isPending}
              className="flex-1"
            >
              <Save size={16} className="mr-2" />
              Save Changes
            </Button>
          </div>
        </div>
      </Modal>

      {/* Preview Modal */}
      <Modal
        isOpen={!!previewHtml}
        onClose={() => setPreviewHtml(null)}
        title="Email Preview"
        size="xl"
      >
        <div className="mb-4 flex items-center justify-between">
          <div className="flex gap-2">
            <Button
              variant={previewDevice === 'desktop' ? 'primary' : 'ghost'}
              size="sm"
              onClick={() => setPreviewDevice('desktop')}
            >
              <Monitor size={14} className="mr-1" />
              Desktop
            </Button>
            <Button
              variant={previewDevice === 'mobile' ? 'primary' : 'ghost'}
              size="sm"
              onClick={() => setPreviewDevice('mobile')}
            >
              <Smartphone size={14} className="mr-1" />
              Mobile
            </Button>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              const blob = new Blob([previewHtml || ''], { type: 'text/html' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'email-preview.html';
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            <Download size={14} className="mr-1" />
            Download
          </Button>
        </div>
        <div 
          className="bg-white rounded-lg border border-[var(--color-border)] overflow-hidden transition-all"
          style={{ 
            maxWidth: previewDevice === 'mobile' ? '375px' : '100%',
            margin: previewDevice === 'mobile' ? '0 auto' : undefined
          }}
        >
          <iframe
            srcDoc={previewHtml || ''}
            className="w-full h-[500px] border-0"
            title="Email Preview"
            style={{ 
              transform: previewDevice === 'mobile' ? 'scale(0.9)' : 'none',
              transformOrigin: 'top center'
            }}
          />
        </div>
      </Modal>

      {/* Test Email Modal */}
      <Modal
        isOpen={testEmailModal}
        onClose={() => setTestEmailModal(false)}
        title="Send Test Email"
      >
        <div className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Send a test email to verify this template renders correctly.
          </p>
          <Input
            label="Recipient Email"
            type="email"
            value={testEmailRecipient}
            onChange={(e) => setTestEmailRecipient(e.target.value)}
            placeholder="test@example.com"
          />
          <div className="flex gap-3 pt-2">
            <Button 
              variant="ghost" 
              onClick={() => setTestEmailModal(false)}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button 
              variant="primary" 
              onClick={handleSendTestEmail}
              isLoading={testEmailMutation.isPending}
              disabled={!testEmailRecipient}
              className="flex-1"
            >
              <Send size={16} className="mr-2" />
              Send Test
            </Button>
          </div>
        </div>
      </Modal>

      {/* Version History Modal */}
      <Modal
        isOpen={versionHistoryModal}
        onClose={() => setVersionHistoryModal(false)}
        title="Version History"
        size="lg"
      >
        <div className="space-y-4">
          {loadingVersions ? (
            <div className="text-center py-8 text-[var(--color-text-secondary)]">
              Loading versions...
            </div>
          ) : versions.length === 0 ? (
            <div className="text-center py-8 text-[var(--color-text-secondary)]">
              <History size={32} className="mx-auto mb-2 opacity-50" />
              <p>No version history available.</p>
              <p className="text-sm mt-1">Versions are created when you save changes.</p>
            </div>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {versions.map((version) => (
                <div 
                  key={version.id}
                  className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-hover)]"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-[var(--color-text-primary)]">
                          Version {version.version}
                        </span>
                        <span className="text-xs text-[var(--color-text-muted)]">
                          {new Date(version.created_at).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                        Subject: {version.subject}
                      </p>
                      {version.change_reason && (
                        <p className="text-xs text-[var(--color-text-muted)] mt-1">
                          Reason: {version.change_reason}
                        </p>
                      )}
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRestoreVersion(version.id)}
                      isLoading={restoreVersionMutation.isPending}
                    >
                      <RotateCcw size={14} className="mr-1" />
                      Restore
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}

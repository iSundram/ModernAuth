import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Palette, Save, Eye } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Input, LoadingBar, Modal } from '../../components/ui';
import { useToast } from '../../components/ui/Toast';
import { adminService } from '../../api/services';
import type { EmailBranding } from '../../types';

export function AdminEmailBrandingPage() {
  const [formData, setFormData] = useState<EmailBranding>({
    app_name: '',
    logo_url: '',
    primary_color: '#2B2B2B',
    secondary_color: '#B3B3B3',
    company_name: '',
    support_email: '',
    footer_text: '',
  });
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch current branding
  const { data: branding, isLoading } = useQuery({
    queryKey: ['email-branding'],
    queryFn: () => adminService.getEmailBranding(),
  });

  // Update form when data loads
  useEffect(() => {
    if (branding) {
      setFormData({
        app_name: branding.app_name || '',
        logo_url: branding.logo_url || '',
        primary_color: branding.primary_color || '#2B2B2B',
        secondary_color: branding.secondary_color || '#B3B3B3',
        company_name: branding.company_name || '',
        support_email: branding.support_email || '',
        footer_text: branding.footer_text || '',
      });
    }
  }, [branding]);

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (data: EmailBranding) => adminService.updateEmailBranding(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-branding'] });
      showToast({ title: 'Success', message: 'Email branding updated successfully', type: 'success' });
      setHasChanges(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update branding', type: 'error' });
    },
  });

  const handleChange = (field: keyof EmailBranding, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setHasChanges(true);
  };

  const handlePreview = async () => {
    try {
      // Preview with the welcome template
      const result = await adminService.previewEmailTemplate('welcome');
      setPreviewHtml(result.html);
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to preview', 
        type: 'error' 
      });
    }
  };

  const handleSave = () => {
    saveMutation.mutate(formData);
  };

  return (
    <div className="space-y-6">
      <LoadingBar isLoading={isLoading} message="Loading branding..." />

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Email Branding</h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Customize the look and feel of your transactional emails.
          </p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" onClick={handlePreview}>
            <Eye size={16} className="mr-2" />
            Preview
          </Button>
          <Button 
            variant="primary" 
            onClick={handleSave}
            isLoading={saveMutation.isPending}
            disabled={!hasChanges}
          >
            <Save size={16} className="mr-2" />
            Save Changes
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Branding Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Palette size={18} />
              Brand Identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              label="App Name"
              value={formData.app_name}
              onChange={(e) => handleChange('app_name', e.target.value)}
              placeholder="ModernAuth"
            />

            <Input
              label="Company Name"
              value={formData.company_name}
              onChange={(e) => handleChange('company_name', e.target.value)}
              placeholder="Your Company Name"
            />

            <Input
              label="Logo URL"
              value={formData.logo_url}
              onChange={(e) => handleChange('logo_url', e.target.value)}
              placeholder="https://example.com/logo.png"
            />

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
                  Primary Color
                </label>
                <div className="flex gap-2">
                  <input
                    type="color"
                    value={formData.primary_color}
                    onChange={(e) => handleChange('primary_color', e.target.value)}
                    className="w-12 h-10 rounded border border-[var(--color-border)] cursor-pointer"
                  />
                  <Input
                    value={formData.primary_color}
                    onChange={(e) => handleChange('primary_color', e.target.value)}
                    placeholder="#4F46E5"
                    className="flex-1"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
                  Secondary Color
                </label>
                <div className="flex gap-2">
                  <input
                    type="color"
                    value={formData.secondary_color}
                    onChange={(e) => handleChange('secondary_color', e.target.value)}
                    className="w-12 h-10 rounded border border-[var(--color-border)] cursor-pointer"
                  />
                  <Input
                    value={formData.secondary_color}
                    onChange={(e) => handleChange('secondary_color', e.target.value)}
                    placeholder="#6B7280"
                    className="flex-1"
                  />
                </div>
              </div>
            </div>

            <Input
              label="Support Email"
              type="email"
              value={formData.support_email}
              onChange={(e) => handleChange('support_email', e.target.value)}
              placeholder="support@example.com"
            />

            <div>
              <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
                Footer Text
              </label>
              <textarea
                value={formData.footer_text}
                onChange={(e) => handleChange('footer_text', e.target.value)}
                className="w-full h-24 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] text-sm resize-none focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
                placeholder="© 2024 Your Company. All rights reserved."
              />
            </div>
          </CardContent>
        </Card>

        {/* Preview Card */}
        <Card>
          <CardHeader>
            <CardTitle>Live Preview</CardTitle>
          </CardHeader>
          <CardContent>
            <div 
              className="p-6 rounded-lg border border-[var(--color-border)]"
              style={{ backgroundColor: '#f9fafb' }}
            >
              {/* Email Header Preview */}
              <div 
                className="p-4 rounded-t-lg text-center"
                style={{ backgroundColor: formData.primary_color }}
              >
                {formData.logo_url ? (
                  <img 
                    src={formData.logo_url} 
                    alt="Logo" 
                    className="h-10 mx-auto"
                    onError={(e) => {
                      (e.target as HTMLImageElement).style.display = 'none';
                    }}
                  />
                ) : (
                  <span className="text-white font-bold text-lg">
                    {formData.company_name || 'Your Company'}
                  </span>
                )}
              </div>

              {/* Email Body Preview */}
              <div className="bg-white p-6 border-x border-[var(--color-border)]">
                <h2 className="text-lg font-semibold text-gray-800 mb-2">
                  Welcome to {formData.company_name || 'Our Platform'}!
                </h2>
                <p className="text-gray-600 text-sm mb-4">
                  This is a preview of how your emails will look with the current branding settings.
                </p>
                <button
                  className="px-4 py-2 rounded text-white text-sm font-medium"
                  style={{ backgroundColor: formData.primary_color }}
                >
                  Call to Action
                </button>
              </div>

              {/* Email Footer Preview */}
              <div 
                className="p-4 rounded-b-lg text-center"
                style={{ backgroundColor: formData.secondary_color }}
              >
                <p className="text-white text-xs">
                  {formData.footer_text || '© 2024 Your Company. All rights reserved.'}
                </p>
                {formData.support_email && (
                  <p className="text-white/80 text-xs mt-1">
                    Need help? Contact us at {formData.support_email}
                  </p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Full Preview Modal */}
      <Modal
        isOpen={!!previewHtml}
        onClose={() => setPreviewHtml(null)}
        title="Email Preview"
        size="xl"
      >
        <div className="bg-white rounded-lg border border-[var(--color-border)] overflow-hidden">
          <iframe
            srcDoc={previewHtml || ''}
            className="w-full h-[500px] border-0"
            title="Email Preview"
          />
        </div>
      </Modal>
    </div>
  );
}

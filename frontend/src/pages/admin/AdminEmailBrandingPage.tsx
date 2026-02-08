import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Palette, Save, Eye, Settings, Type, Share2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/Card';
import { Button, Input, LoadingBar, Modal } from '../../components/ui';
import { useToast } from '../../components/ui/Toast';
import { adminService } from '../../api/services';
import type { EmailBranding, EmailBrandingAdvanced } from '../../types';

export function AdminEmailBrandingPage() {
  const [formData, setFormData] = useState<EmailBranding | null>(null);
  const [advancedData, setAdvancedData] = useState<EmailBrandingAdvanced | null>(null);
  
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [hasChanges, setHasChanges] = useState(false);
  const [activeTab, setActiveTab] = useState<'basic' | 'advanced'>('basic');

  const { showToast } = useToast();
  const queryClient = useQueryClient();

  // Fetch current branding
  const { data: branding, isLoading } = useQuery({
    queryKey: ['email-branding'],
    queryFn: () => adminService.getEmailBranding(),
  });

  // Fetch advanced branding
  const { data: advancedBranding } = useQuery<EmailBrandingAdvanced>({
    queryKey: ['email-branding-advanced'],
    queryFn: () => adminService.getEmailBrandingAdvanced?.() || Promise.resolve({} as EmailBrandingAdvanced),
    enabled: activeTab === 'advanced',
  });

  // Derive default form data from query results
  const defaultFormData = useMemo<EmailBranding>(() => ({
    app_name: branding?.app_name || '',
    logo_url: branding?.logo_url || '',
    primary_color: branding?.primary_color || '#2B2B2B',
    secondary_color: branding?.secondary_color || '#B3B3B3',
    company_name: branding?.company_name || '',
    support_email: branding?.support_email || '',
    footer_text: branding?.footer_text || '',
  }), [branding]);

  const defaultAdvancedData = useMemo<EmailBrandingAdvanced>(() => ({
    social_links: advancedBranding?.social_links || { facebook: '', twitter: '', linkedin: '', instagram: '' },
    custom_css: advancedBranding?.custom_css || '',
    font_family: advancedBranding?.font_family || '',
    font_family_url: advancedBranding?.font_family_url || '',
    header_image_url: advancedBranding?.header_image_url || '',
  }), [advancedBranding]);

  // Merge local edits over server defaults
  const effectiveFormData = formData ?? defaultFormData;
  const effectiveAdvancedData = advancedData ?? defaultAdvancedData;

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (data: EmailBranding) => adminService.updateEmailBranding(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-branding'] });
      showToast({ title: 'Success', message: 'Email branding updated successfully', type: 'success' });
      setFormData(null);
      setHasChanges(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update branding', type: 'error' });
    },
  });

  // Save advanced mutation
  const saveAdvancedMutation = useMutation({
    mutationFn: (data: EmailBrandingAdvanced) => adminService.updateEmailBrandingAdvanced?.(data) || Promise.resolve(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-branding-advanced'] });
      showToast({ title: 'Success', message: 'Advanced branding updated successfully', type: 'success' });
      setAdvancedData(null);
      setHasChanges(false);
    },
    onError: (error: Error) => {
      showToast({ title: 'Error', message: error.message || 'Failed to update advanced branding', type: 'error' });
    },
  });

  const handleChange = (field: keyof EmailBranding, value: string) => {
    setFormData(prev => ({ ...(prev ?? defaultFormData), [field]: value }));
    setHasChanges(true);
  };

  const handleAdvancedChange = (field: string, value: string) => {
    if (field.startsWith('social_')) {
      const social = field.replace('social_', '') as keyof typeof effectiveAdvancedData.social_links;
      setAdvancedData(prev => ({
        ...(prev ?? defaultAdvancedData),
        social_links: { ...(prev ?? defaultAdvancedData).social_links!, [social]: value }
      }));
    } else {
      setAdvancedData(prev => ({ ...(prev ?? defaultAdvancedData), [field]: value }) as EmailBrandingAdvanced);
    }
    setHasChanges(true);
  };

  const handlePreview = async () => {
    try {
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
    if (activeTab === 'basic') {
      saveMutation.mutate(effectiveFormData);
    } else {
      saveAdvancedMutation.mutate(effectiveAdvancedData);
    }
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
            isLoading={saveMutation.isPending || saveAdvancedMutation.isPending}
            disabled={!hasChanges}
          >
            <Save size={16} className="mr-2" />
            Save Changes
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-[var(--color-border)] pb-2">
        <Button
          variant={activeTab === 'basic' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('basic')}
        >
          <Palette size={14} className="mr-2" />
          Basic
        </Button>
        <Button
          variant={activeTab === 'advanced' ? 'primary' : 'ghost'}
          size="sm"
          onClick={() => setActiveTab('advanced')}
        >
          <Settings size={14} className="mr-2" />
          Advanced
        </Button>
      </div>

      {activeTab === 'basic' ? (
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
                value={effectiveFormData.app_name}
                onChange={(e) => handleChange('app_name', e.target.value)}
                placeholder="ModernAuth"
              />

              <Input
                label="Company Name"
                value={effectiveFormData.company_name}
                onChange={(e) => handleChange('company_name', e.target.value)}
                placeholder="Your Company Name"
              />

              <Input
                label="Logo URL"
                value={effectiveFormData.logo_url}
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
                      value={effectiveFormData.primary_color}
                      onChange={(e) => handleChange('primary_color', e.target.value)}
                      className="w-12 h-10 rounded border border-[var(--color-border)] cursor-pointer"
                    />
                    <Input
                      value={effectiveFormData.primary_color}
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
                      value={effectiveFormData.secondary_color}
                      onChange={(e) => handleChange('secondary_color', e.target.value)}
                      className="w-12 h-10 rounded border border-[var(--color-border)] cursor-pointer"
                    />
                    <Input
                      value={effectiveFormData.secondary_color}
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
                value={effectiveFormData.support_email}
                onChange={(e) => handleChange('support_email', e.target.value)}
                placeholder="support@example.com"
              />

              <div>
                <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
                  Footer Text
                </label>
                <textarea
                  value={effectiveFormData.footer_text}
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
                  style={{ backgroundColor: effectiveFormData.primary_color }}
                >
                  {effectiveFormData.logo_url ? (
                    <img 
                      src={effectiveFormData.logo_url} 
                      alt="Logo" 
                      className="h-10 mx-auto"
                      onError={(e) => {
                        (e.target as HTMLImageElement).style.display = 'none';
                      }}
                    />
                  ) : (
                    <span className="text-white font-bold text-lg">
                      {effectiveFormData.company_name || 'Your Company'}
                    </span>
                  )}
                </div>

                {/* Email Body Preview */}
                <div className="bg-white p-6 border-x border-[var(--color-border)]">
                  <h2 className="text-lg font-semibold text-gray-800 mb-2">
                    Welcome to {effectiveFormData.company_name || 'Our Platform'}!
                  </h2>
                  <p className="text-gray-600 text-sm mb-4">
                    This is a preview of how your emails will look with the current branding settings.
                  </p>
                  <button
                    className="px-4 py-2 rounded text-white text-sm font-medium"
                    style={{ backgroundColor: effectiveFormData.primary_color }}
                  >
                    Call to Action
                  </button>
                </div>

                {/* Email Footer Preview */}
                <div 
                  className="p-4 rounded-b-lg text-center"
                  style={{ backgroundColor: effectiveFormData.secondary_color }}
                >
                  <p className="text-white text-xs">
                    {effectiveFormData.footer_text || '© 2024 Your Company. All rights reserved.'}
                  </p>
                  {effectiveFormData.support_email && (
                    <p className="text-white/80 text-xs mt-1">
                      Need help? Contact us at {effectiveFormData.support_email}
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Advanced Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Type size={18} />
                Typography & Styles
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                label="Font Family Name"
                value={effectiveAdvancedData.font_family}
                onChange={(e) => handleAdvancedChange('font_family', e.target.value)}
                placeholder="Inter, Arial, sans-serif"
              />

              <Input
                label="Font Family URL (Google Fonts)"
                value={effectiveAdvancedData.font_family_url}
                onChange={(e) => handleAdvancedChange('font_family_url', e.target.value)}
                placeholder="https://fonts.googleapis.com/css2?family=Inter..."
              />

              <Input
                label="Header Image URL"
                value={effectiveAdvancedData.header_image_url}
                onChange={(e) => handleAdvancedChange('header_image_url', e.target.value)}
                placeholder="https://example.com/header.jpg"
              />

              <div>
                <label className="block text-sm font-medium text-[var(--color-text-primary)] mb-2">
                  Custom CSS
                </label>
                <textarea
                  value={effectiveAdvancedData.custom_css}
                  onChange={(e) => handleAdvancedChange('custom_css', e.target.value)}
                  className="w-full h-32 p-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)]"
                  placeholder=".email-container { max-width: 600px; }"
                />
              </div>
            </CardContent>
          </Card>

          {/* Social Links */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Share2 size={18} />
                Social Media Links
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                label="Facebook"
                value={effectiveAdvancedData.social_links?.facebook || ''}
                onChange={(e) => handleAdvancedChange('social_facebook', e.target.value)}
                placeholder="https://facebook.com/yourcompany"
                leftIcon={<span className="text-blue-500">f</span>}
              />

              <Input
                label="Twitter/X"
                value={effectiveAdvancedData.social_links?.twitter || ''}
                onChange={(e) => handleAdvancedChange('social_twitter', e.target.value)}
                placeholder="https://twitter.com/yourcompany"
                leftIcon={<span className="text-black">𝕏</span>}
              />

              <Input
                label="LinkedIn"
                value={effectiveAdvancedData.social_links?.linkedin || ''}
                onChange={(e) => handleAdvancedChange('social_linkedin', e.target.value)}
                placeholder="https://linkedin.com/company/yourcompany"
                leftIcon={<span className="text-blue-600">in</span>}
              />

              <Input
                label="Instagram"
                value={effectiveAdvancedData.social_links?.instagram || ''}
                onChange={(e) => handleAdvancedChange('social_instagram', e.target.value)}
                placeholder="https://instagram.com/yourcompany"
                leftIcon={<span className="text-pink-500">📷</span>}
              />
            </CardContent>
          </Card>
        </div>
      )}

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

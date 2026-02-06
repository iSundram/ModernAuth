import { useState, useEffect, useCallback } from 'react';
import { tenantService } from '../api/services';
import { useAuth } from './useAuth';
import type { Tenant, TenantFeatures, TenantStats, TenantSecurityStats, TenantOnboardingStatusResponse } from '../types';

interface UseTenantReturn {
  tenant: Tenant | null;
  features: TenantFeatures | null;
  stats: TenantStats | null;
  securityStats: TenantSecurityStats | null;
  onboardingStatus: TenantOnboardingStatusResponse | null;
  isLoading: boolean;
  error: Error | null;
  refreshTenant: () => Promise<void>;
  refreshStats: () => Promise<void>;
  updateFeatures: (features: Partial<TenantFeatures>) => Promise<void>;
  refreshOnboardingStatus: () => Promise<void>;
}

export function useTenant(tenantId?: string): UseTenantReturn {
  const { user } = useAuth();
  // Fall back to the current user's tenant_id if no explicit tenantId is provided
  const resolvedTenantId = tenantId || user?.tenant_id;
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [features, setFeatures] = useState<TenantFeatures | null>(null);
  const [stats, setStats] = useState<TenantStats | null>(null);
  const [securityStats, setSecurityStats] = useState<TenantSecurityStats | null>(null);
  const [onboardingStatus, setOnboardingStatus] = useState<TenantOnboardingStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchTenantData = useCallback(async () => {
    if (!resolvedTenantId) return;

    setIsLoading(true);
    setError(null);

    try {
      const [tenantData, featuresData, onboardingData] = await Promise.all([
        tenantService.get(resolvedTenantId),
        tenantService.getFeatures(resolvedTenantId),
        tenantService.getOnboardingStatus(resolvedTenantId)
      ]);

      setTenant(tenantData);
      setFeatures(featuresData);
      setOnboardingStatus(onboardingData);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch tenant data'));
    } finally {
      setIsLoading(false);
    }
  }, [resolvedTenantId]);

  const fetchStats = useCallback(async () => {
    if (!resolvedTenantId) return;

    try {
      const [statsData, securityStatsData] = await Promise.all([
        tenantService.getStats(resolvedTenantId),
        tenantService.getSecurityStats(resolvedTenantId),
      ]);

      setStats(statsData);
      setSecurityStats(securityStatsData);
    } catch (err) {
      // Don't set global error for stats failure
      console.error('Failed to fetch tenant stats:', err);
    }
  }, [resolvedTenantId]);

  const updateFeatures = useCallback(async (newFeatures: Partial<TenantFeatures>) => {
    if (!resolvedTenantId) return;

    try {
      const updated = await tenantService.updateFeatures(resolvedTenantId, newFeatures);
      setFeatures(updated);
      // Refresh onboarding status as features might affect it
      const status = await tenantService.getOnboardingStatus(resolvedTenantId);
      setOnboardingStatus(status);
    } catch (err) {
      throw err instanceof Error ? err : new Error('Failed to update features');
    }
  }, [resolvedTenantId]);

  const refreshOnboardingStatus = useCallback(async () => {
    if (!resolvedTenantId) return;
    try {
      const status = await tenantService.getOnboardingStatus(resolvedTenantId);
      setOnboardingStatus(status);
    } catch (err) {
      console.error('Failed to refresh onboarding status:', err);
    }
  }, [resolvedTenantId]);

  useEffect(() => {
    fetchTenantData();
    fetchStats();
  }, [fetchTenantData, fetchStats]);

  return {
    tenant,
    features,
    stats,
    securityStats,
    onboardingStatus,
    isLoading,
    error,
    refreshTenant: fetchTenantData,
    refreshStats: fetchStats,
    updateFeatures,
    refreshOnboardingStatus
  };
}

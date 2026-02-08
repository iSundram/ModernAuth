import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authService } from '../api/services';
import type { UpdatePreferencesRequest, UpdateProfileRequest } from '../types';

export function usePreferences() {
  return useQuery({
    queryKey: ['preferences'],
    queryFn: () => authService.getPreferences(),
  });
}

export function useUpdatePreferences() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: UpdatePreferencesRequest) => authService.updatePreferences(data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['preferences'] }),
  });
}

export function useUpdateProfile() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: UpdateProfileRequest) => authService.updateProfile(data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['auth', 'me'] }),
  });
}

export function useExportData() {
  return useMutation({
    mutationFn: () => authService.exportData(),
  });
}

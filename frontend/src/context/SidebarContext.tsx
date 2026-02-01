import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

interface SidebarContextType {
  isCollapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  collapse: () => void;
  expand: () => void;
  toggle: () => void;
  storageKey: string;
}

const SidebarContext = createContext<SidebarContextType | undefined>(undefined);

interface SidebarProviderProps {
  children: ReactNode;
  storageKey: string;
  defaultCollapsed?: boolean;
}

export function SidebarProvider({ children, storageKey, defaultCollapsed = true }: SidebarProviderProps) {
  const [isCollapsed, setIsCollapsed] = useState(() => {
    const saved = localStorage.getItem(storageKey);
    return saved !== null ? JSON.parse(saved) : defaultCollapsed;
  });

  const setCollapsed = useCallback((collapsed: boolean) => {
    setIsCollapsed(collapsed);
    localStorage.setItem(storageKey, JSON.stringify(collapsed));
  }, [storageKey]);

  const collapse = useCallback(() => setCollapsed(true), [setCollapsed]);
  const expand = useCallback(() => setCollapsed(false), [setCollapsed]);
  const toggle = useCallback(() => setCollapsed(!isCollapsed), [isCollapsed, setCollapsed]);

  return (
    <SidebarContext.Provider value={{ isCollapsed, setCollapsed, collapse, expand, toggle, storageKey }}>
      {children}
    </SidebarContext.Provider>
  );
}

export function useSidebar() {
  const context = useContext(SidebarContext);
  if (!context) {
    throw new Error('useSidebar must be used within a SidebarProvider');
  }
  return context;
}

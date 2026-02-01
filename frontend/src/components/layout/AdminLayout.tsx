import { Outlet } from 'react-router-dom';
import { AdminSidebar } from './AdminSidebar';
import { Header } from './Header';
import { EmailVerificationBanner } from '../ui';
import { ImpersonationBanner } from './ImpersonationBanner';
import { SidebarProvider, useSidebar } from '../../context/SidebarContext';

function AdminLayoutContent() {
  const { isCollapsed, collapse } = useSidebar();

  // Collapse sidebar when clicking on main content (only if expanded)
  const handleContentClick = () => {
    if (!isCollapsed) {
      collapse();
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <ImpersonationBanner />
      <div className="flex-1 flex min-h-0">
        <AdminSidebar />
        <div className="flex-1 flex flex-col min-h-0" onClick={handleContentClick}>
          <Header />
          <EmailVerificationBanner />
          <main className="flex-1 overflow-auto bg-[var(--color-background)] p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}

export function AdminLayout() {
  return (
    <SidebarProvider storageKey="adminSidebarCollapsed" defaultCollapsed={true}>
      <AdminLayoutContent />
    </SidebarProvider>
  );
}

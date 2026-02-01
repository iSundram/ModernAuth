import { Outlet } from 'react-router-dom';
import { UserSidebar } from './UserSidebar';
import { Header } from './Header';
import { EmailVerificationBanner } from '../ui';
import { ImpersonationBanner } from './ImpersonationBanner';
import { SidebarProvider, useSidebar } from '../../context/SidebarContext';

function UserLayoutContent() {
  const { isCollapsed, collapse } = useSidebar();

  // Collapse sidebar when clicking on main content (only if expanded)
  const handleContentClick = () => {
    if (!isCollapsed) {
      collapse();
    }
  };

  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <ImpersonationBanner />
      <div className="flex-1 flex min-h-0">
        <UserSidebar />
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

export function UserLayout() {
  return (
    <SidebarProvider storageKey="userSidebarCollapsed" defaultCollapsed={true}>
      <UserLayoutContent />
    </SidebarProvider>
  );
}

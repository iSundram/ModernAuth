import { Outlet } from 'react-router-dom';
import { AdminSidebar } from './AdminSidebar';
import { Header } from './Header';
import { EmailVerificationBanner } from '../ui';

export function AdminLayout() {
  return (
    <div className="h-screen flex overflow-hidden">
      <AdminSidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <EmailVerificationBanner />
        <main className="flex-1 overflow-auto bg-[var(--color-background)] p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

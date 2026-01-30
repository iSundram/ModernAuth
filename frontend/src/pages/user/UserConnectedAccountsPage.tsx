import { LinkedAccounts } from '../../components/security';

export function UserConnectedAccountsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Connected Accounts</h1>
        <p className="text-[var(--color-text-secondary)] mt-1">
          Manage your linked social accounts for easier sign-in.
        </p>
      </div>

      <LinkedAccounts />
    </div>
  );
}

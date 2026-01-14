import { Card, CardContent } from './ui/Card';
import { Construction } from 'lucide-react';

interface PlaceholderPageProps {
  title: string;
  description?: string;
  features?: string[];
}

export function PlaceholderPage({ title, description, features }: PlaceholderPageProps) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">{title}</h1>
        {description && (
          <p className="text-[var(--color-text-secondary)] mt-1">{description}</p>
        )}
      </div>

      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <div className="p-4 rounded-full bg-[var(--color-primary-dark)]/50 mb-4">
            <Construction size={48} className="text-[#D4D4D4]" />
          </div>
          <h2 className="text-xl font-semibold text-[var(--color-text-primary)] mb-2">
            Feature Under Development
          </h2>
          <p className="text-[var(--color-text-secondary)] text-center max-w-md mb-6">
            This feature is currently being developed and will be available soon.
          </p>
          {features && features.length > 0 && (
            <div className="w-full max-w-md">
              <p className="text-sm font-medium text-[var(--color-text-secondary)] mb-3">
                Planned Features:
              </p>
              <ul className="space-y-2">
                {features.map((feature, index) => (
                  <li
                    key={index}
                    className="flex items-start gap-2 text-sm text-[var(--color-text-muted)]"
                  >
                    <span className="text-[#D4D4D4] mt-1">•</span>
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

import { useEffect, useRef, useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { authService } from '../../api/services';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type CaptchaProvider = 'none' | 'recaptcha_v2' | 'recaptcha_v3' | 'turnstile';

interface CaptchaWidgetProps {
  /** Called with the CAPTCHA response token (or empty string on expiry). */
  onToken: (token: string) => void;
  /**
   * reCAPTCHA v3 action name (defaults to "submit").
   * Ignored by v2 and Turnstile.
   */
  action?: string;
}

interface GrecaptchaInstance {
  render: (container: HTMLElement, options: Record<string, unknown>) => number;
  ready: (callback: () => void) => void;
  execute: (siteKey: string, options: { action: string }) => Promise<string>;
  reset: (widgetId: number) => void;
}

interface TurnstileInstance {
  render: (container: HTMLElement, options: Record<string, unknown>) => string;
  remove: (widgetId: string) => void;
}

declare global {
  interface Window {
    grecaptcha?: GrecaptchaInstance;
    turnstile?: TurnstileInstance;
  }
}

// Script load state shared across all mounts so we only inject once.
const loadedScripts = new Set<string>();

// ---------------------------------------------------------------------------
// Helpers – dynamic script loading
// ---------------------------------------------------------------------------

function loadScript(src: string): Promise<void> {
  if (loadedScripts.has(src)) return Promise.resolve();

  return new Promise((resolve, reject) => {
    // Check if already in DOM (e.g. hot-reload).
    const existing = document.querySelector(`script[src="${src}"]`);
    if (existing) {
      loadedScripts.add(src);
      resolve();
      return;
    }

    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.defer = true;
    script.onload = () => {
      loadedScripts.add(src);
      resolve();
    };
    script.onerror = () => reject(new Error(`Failed to load script: ${src}`));
    document.head.appendChild(script);
  });
}

// ---------------------------------------------------------------------------
// reCAPTCHA v2 sub-component
// ---------------------------------------------------------------------------

function RecaptchaV2Widget({
  siteKey,
  onToken,
}: {
  siteKey: string;
  onToken: (t: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    const render = () => {
      if (cancelled || !containerRef.current) return;
      const grecaptcha = window.grecaptcha;
      if (!grecaptcha?.render) return;

      // Avoid duplicate renders.
      if (widgetIdRef.current !== null) return;

      widgetIdRef.current = grecaptcha.render(containerRef.current, {
        sitekey: siteKey,
        callback: (token: string) => onToken(token),
        'expired-callback': () => onToken(''),
        'error-callback': () => onToken(''),
      });
    };

    loadScript('https://www.google.com/recaptcha/api.js?render=explicit')
      .then(() => {
        // grecaptcha.ready fires once the library is fully initialised.
        const grecaptcha = window.grecaptcha;
        if (grecaptcha?.ready) {
          grecaptcha.ready(render);
        } else {
          // Fallback: poll briefly.
          const iv = setInterval(() => {
            if (window.grecaptcha?.render) {
              clearInterval(iv);
              render();
            }
          }, 200);
          setTimeout(() => clearInterval(iv), 10000);
        }
      })
      .catch(() => {
        /* script failed – silently degrade */
      });

    return () => {
      cancelled = true;
      if (widgetIdRef.current !== null) {
        try {
          window.grecaptcha?.reset?.(widgetIdRef.current);
        } catch {
          /* ignore */
        }
        widgetIdRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey]);

  return <div ref={containerRef} className="flex justify-center my-3" />;
}

// ---------------------------------------------------------------------------
// reCAPTCHA v3 sub-component (invisible)
// ---------------------------------------------------------------------------

function RecaptchaV3Widget({
  siteKey,
  onToken,
  action = 'submit',
}: {
  siteKey: string;
  onToken: (t: string) => void;
  action?: string;
}) {
  const executedRef = useRef(false);

  const execute = useCallback(() => {
    const grecaptcha = window.grecaptcha;
    if (!grecaptcha?.execute) return;

    grecaptcha
      .execute(siteKey, { action })
      .then((token: string) => onToken(token))
      .catch(() => onToken(''));
  }, [siteKey, action, onToken]);

  useEffect(() => {
    let cancelled = false;

    loadScript(`https://www.google.com/recaptcha/api.js?render=${siteKey}`)
      .then(() => {
        if (cancelled) return;
        const grecaptcha = window.grecaptcha;
        if (grecaptcha?.ready) {
          grecaptcha.ready(() => {
            if (!cancelled && !executedRef.current) {
              executedRef.current = true;
              execute();
            }
          });
        }
      })
      .catch(() => {
        /* silent */
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey, action]);

  // Re-execute is available via the parent re-mounting or calling onToken('') then re-rendering.
  return null; // invisible
}

// ---------------------------------------------------------------------------
// Cloudflare Turnstile sub-component
// ---------------------------------------------------------------------------

function TurnstileWidget({
  siteKey,
  onToken,
}: {
  siteKey: string;
  onToken: (t: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const render = () => {
      if (cancelled || !containerRef.current) return;
      const turnstile = window.turnstile;
      if (!turnstile?.render) return;
      if (widgetIdRef.current !== null) return;

      widgetIdRef.current = turnstile.render(containerRef.current, {
        sitekey: siteKey,
        callback: (token: string) => onToken(token),
        'expired-callback': () => onToken(''),
        'error-callback': () => onToken(''),
      });
    };

    loadScript('https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit')
      .then(() => {
        if (cancelled) return;
        // Turnstile auto-initialises quickly; poll briefly.
        const iv = setInterval(() => {
          if (window.turnstile?.render) {
            clearInterval(iv);
            render();
          }
        }, 200);
        setTimeout(() => clearInterval(iv), 10000);
      })
      .catch(() => {
        /* silent */
      });

    return () => {
      cancelled = true;
      if (widgetIdRef.current !== null) {
        try {
          window.turnstile?.remove?.(widgetIdRef.current);
        } catch {
          /* ignore */
        }
        widgetIdRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey]);

  return <div ref={containerRef} className="flex justify-center my-3" />;
}

// ---------------------------------------------------------------------------
// Main CaptchaWidget – auto-detects provider from API
// ---------------------------------------------------------------------------

export function CaptchaWidget({ onToken, action = 'submit' }: CaptchaWidgetProps) {
  const { data } = useQuery({
    queryKey: ['captcha-config'],
    queryFn: () => authService.getCaptchaConfig(),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const provider = useMemo<CaptchaProvider>(() => {
    return (data?.provider || 'none') as CaptchaProvider;
  }, [data]);

  const siteKey = useMemo(() => {
    return data?.site_key || '';
  }, [data]);

  if (provider === 'none' || !siteKey) return null;

  switch (provider) {
    case 'recaptcha_v2':
      return <RecaptchaV2Widget siteKey={siteKey} onToken={onToken} />;
    case 'recaptcha_v3':
      return (
        <RecaptchaV3Widget siteKey={siteKey} onToken={onToken} action={action} />
      );
    case 'turnstile':
      return <TurnstileWidget siteKey={siteKey} onToken={onToken} />;
    default:
      return null;
  }
}

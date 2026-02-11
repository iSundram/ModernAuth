/**
 * Generates a simple device fingerprint based on browser properties.
 * In production, you might want to use a library like FingerprintJS.
 */
export async function getDeviceFingerprint(): Promise<string> {
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.colorDepth,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    !!window.sessionStorage,
    !!window.localStorage,
    !!window.indexedDB,
  ];

  const fingerprintSource = components.join('|');
  
  // SubtleCrypto is only available in secure contexts (HTTPS or localhost)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    // Use SubtleCrypto to create a SHA-256 hash
    const msgUint8 = new TextEncoder().encode(fingerprintSource);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Fallback for non-secure contexts: Simple non-cryptographic hash
  let hash = 0;
  for (let i = 0; i < fingerprintSource.length; i++) {
    const char = fingerprintSource.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return 'fallback-' + Math.abs(hash).toString(16);
}

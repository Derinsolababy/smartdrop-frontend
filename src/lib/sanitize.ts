/**
 * URL sanitisation helpers used across the app to prevent open-redirect and
 * XSS vectors from untrusted input.
 */

const SAFE_PROTOCOLS = new Set(['https:', 'http:']);

/**
 * Validates and normalises a URL that must use http or https.
 *
 * Protocol-relative URLs (e.g. `//example.com/path`) are promoted to `https:`
 * before parsing so they don't bypass the protocol check (#745).
 *
 * @param value        - Untrusted input.
 * @param allowedHosts - Optional allowlist of hostnames; rejects anything else.
 * @returns The normalised URL string, or `undefined` if the input is invalid.
 */
export function safeHttpUrl(
  value: unknown,
  allowedHosts?: readonly string[],
): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;

  let normalized = value.trim();

  // Promote protocol-relative URLs to https so `new URL()` can parse them
  // and the SAFE_PROTOCOLS check catches any downstream abuse.
  if (normalized.startsWith('//')) normalized = `https:${normalized}`;

  try {
    const parsed = new URL(normalized);
    if (!SAFE_PROTOCOLS.has(parsed.protocol)) return undefined;
    if (allowedHosts && !allowedHosts.includes(parsed.hostname)) return undefined;
    return parsed.toString();
  } catch {
    return undefined;
  }
}

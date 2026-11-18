import { describe, expect, it } from 'vitest';
import { safeHttpUrl } from './sanitize';

describe('safeHttpUrl', () => {
  it('accepts a valid https URL', () => {
    expect(safeHttpUrl('https://example.com/path')).toBe('https://example.com/path');
  });

  it('accepts a valid http URL', () => {
    expect(safeHttpUrl('http://example.com/')).toBe('http://example.com/');
  });

  it('promotes protocol-relative URLs to https (#745)', () => {
    expect(safeHttpUrl('//example.com/path')).toBe('https://example.com/path');
  });

  it('rejects javascript: URLs', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeUndefined();
  });

  it('rejects data: URLs', () => {
    expect(safeHttpUrl('data:text/html,<script>alert(1)</script>')).toBeUndefined();
  });

  it('rejects empty string', () => {
    expect(safeHttpUrl('')).toBeUndefined();
  });

  it('rejects non-string input', () => {
    expect(safeHttpUrl(null)).toBeUndefined();
    expect(safeHttpUrl(42)).toBeUndefined();
  });

  it('rejects a hostname not in the allowedHosts list', () => {
    expect(safeHttpUrl('https://evil.com', ['example.com'])).toBeUndefined();
  });

  it('accepts a hostname in the allowedHosts list', () => {
    expect(safeHttpUrl('https://example.com/page', ['example.com'])).toBe('https://example.com/page');
  });

  it('rejects a protocol-relative URL whose host is not in allowedHosts', () => {
    expect(safeHttpUrl('//evil.com', ['example.com'])).toBeUndefined();
  });
});

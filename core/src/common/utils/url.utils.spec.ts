import {
  normalizeUrl,
  extractDomain,
  buildUrlWithParam,
  isAbsoluteUrl,
  isSameDomain,
} from './url.utils';

describe('url.utils', () => {
  describe('normalizeUrl', () => {
    it('strips trailing slash', () => {
      expect(normalizeUrl('https://example.com/')).toBe('https://example.com');
    });

    it('preserves path without trailing slash', () => {
      expect(normalizeUrl('https://example.com/path')).toBe(
        'https://example.com/path',
      );
    });

    it('throws on invalid url', () => {
      expect(() => normalizeUrl('not-a-url')).toThrow('Invalid URL');
    });

    it('keeps query parameters', () => {
      const url = normalizeUrl('https://example.com/search?q=hello');
      expect(url).toContain('q=hello');
    });
  });

  describe('extractDomain', () => {
    it('extracts hostname from url', () => {
      expect(extractDomain('https://example.com/path')).toBe('example.com');
    });

    it('extracts hostname with subdomain', () => {
      expect(extractDomain('https://sub.example.com')).toBe('sub.example.com');
    });
  });

  describe('buildUrlWithParam', () => {
    it('adds query parameter to url', () => {
      const result = buildUrlWithParam('https://example.com', 'q', 'test');
      expect(result).toContain('q=test');
    });

    it('overwrites existing param', () => {
      const result = buildUrlWithParam(
        'https://example.com?q=old',
        'q',
        'new',
      );
      expect(result).toContain('q=new');
      expect(result).not.toContain('q=old');
    });
  });

  describe('isAbsoluteUrl', () => {
    it('returns true for http urls', () => {
      expect(isAbsoluteUrl('http://example.com')).toBe(true);
    });

    it('returns true for https urls', () => {
      expect(isAbsoluteUrl('https://example.com')).toBe(true);
    });

    it('returns false for relative paths', () => {
      expect(isAbsoluteUrl('/path/page')).toBe(false);
    });

    it('returns false for protocol-relative urls', () => {
      expect(isAbsoluteUrl('//example.com')).toBe(false);
    });
  });

  describe('isSameDomain', () => {
    it('returns true for same domain', () => {
      expect(
        isSameDomain('https://example.com/a', 'https://example.com/b'),
      ).toBe(true);
    });

    it('returns false for different domains', () => {
      expect(
        isSameDomain('https://example.com', 'https://other.com'),
      ).toBe(false);
    });

    it('returns false for invalid urls', () => {
      expect(isSameDomain('not-a-url', 'also-not')).toBe(false);
    });
  });
});

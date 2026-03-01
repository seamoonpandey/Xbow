export function normalizeUrl(raw: string): string {
  try {
    const u = new URL(raw);
    // strip trailing slash
    return u.toString().replace(/\/$/, '');
  } catch {
    throw new Error(`Invalid URL: ${raw}`);
  }
}

export function extractDomain(url: string): string {
  return new URL(url).hostname;
}

export function buildUrlWithParam(
  base: string,
  param: string,
  value: string,
): string {
  const u = new URL(base);
  u.searchParams.set(param, value);
  return u.toString();
}

export function isAbsoluteUrl(url: string): boolean {
  return url.startsWith('http://') || url.startsWith('https://');
}

export function isSameDomain(base: string, target: string): boolean {
  try {
    return new URL(base).hostname === new URL(target).hostname;
  } catch {
    return false;
  }
}

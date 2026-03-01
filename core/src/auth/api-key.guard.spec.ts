import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiKeyGuard } from './api-key.guard';

function mockExecutionContext(path: string, headers: Record<string, string> = {}) {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        path,
        headers,
      }),
    }),
  } as any;
}

describe('ApiKeyGuard', () => {
  let guard: ApiKeyGuard;
  let config: ConfigService;

  describe('with API_KEY_SECRET configured', () => {
    beforeEach(() => {
      config = { get: jest.fn().mockReturnValue('super-secret') } as any;
      guard = new ApiKeyGuard(config);
    });

    it('allows /health without api key', () => {
      const ctx = mockExecutionContext('/health');
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('allows valid x-api-key header', () => {
      const ctx = mockExecutionContext('/scan', { 'x-api-key': 'super-secret' });
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('allows valid Bearer token', () => {
      const ctx = mockExecutionContext('/scan', {
        authorization: 'Bearer super-secret',
      });
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('throws UnauthorizedException on missing key', () => {
      const ctx = mockExecutionContext('/scan');
      expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException on wrong key', () => {
      const ctx = mockExecutionContext('/scan', { 'x-api-key': 'wrong' });
      expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
    });
  });

  describe('without API_KEY_SECRET (dev mode)', () => {
    beforeEach(() => {
      config = { get: jest.fn().mockReturnValue(undefined) } as any;
      guard = new ApiKeyGuard(config);
    });

    it('allows any request when no secret is configured', () => {
      const ctx = mockExecutionContext('/scan');
      expect(guard.canActivate(ctx)).toBe(true);
    });
  });
});

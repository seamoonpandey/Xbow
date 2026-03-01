import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    // health endpoint is always public
    if (req.path === '/health') return true;

    const key =
      req.headers['x-api-key'] ??
      req.headers['authorization']?.replace('Bearer ', '');

    const expected = this.config.get<string>('API_KEY_SECRET');
    if (!expected) return true; // no key configured → open (dev mode)

    if (!key || key !== expected) {
      throw new UnauthorizedException('invalid or missing api key');
    }
    return true;
  }
}

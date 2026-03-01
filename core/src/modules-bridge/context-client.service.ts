import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';

export interface AnalyzeRequest {
  url: string;
  params: string[];
  waf: string;
}

export type ContextMap = Record<
  string,
  {
    reflects_in: string;
    allowed_chars: string[];
    context_confidence: number;
  }
>;

@Injectable()
export class ContextClientService {
  private readonly logger = new Logger(ContextClientService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    this.baseUrl = this.config.get<string>(
      'CONTEXT_URL',
      'http://localhost:5001',
    );
  }

  async analyze(req: AnalyzeRequest): Promise<ContextMap> {
    try {
      const { data } = await firstValueFrom(
        this.http.post<ContextMap>(`${this.baseUrl}/analyze`, req),
      );
      this.logger.log(`context module responded for ${req.url}`);
      return data;
    } catch (err) {
      let detail = 'unknown';
      if (err instanceof Error) {
        detail = err.message;
      } else if (typeof err === 'object' && err !== null) {
        const response = (err as Record<string, unknown>)?.response;
        if (typeof response === 'object' && response !== null) {
          const data = (response as Record<string, unknown>)?.data;
          if (typeof data === 'object' && data !== null) {
            const detailValue = (data as Record<string, unknown>)?.detail;
            if (typeof detailValue === 'string') {
              detail = detailValue;
            }
          }
        }
      }
      throw new PythonModuleException('context', detail);
    }
  }
}

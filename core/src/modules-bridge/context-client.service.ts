import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';
import type { AuthSession } from '../common/interfaces/auth.interface';

export interface AnalyzeRequest {
  url: string;
  params: string[];
  waf: string;
  /** Optional: flat cookie header to forward to the Python context module */
  cookieHeader?: string;
  /** Form method for form-based context probing (GET | POST) */
  formMethod?: string;
  /** Required form field names for form-based probing */
  formFields?: string[];
  /** Page where stored output appears (for stored XSS context probing) */
  displayUrl?: string;
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
    this.baseUrl = this.config.get<string>('CONTEXT_URL', 'http://localhost:5001');
  }

  /**
   * Analyse reflection contexts for the given URL/params.
   * When `authSession` is provided the session cookies are forwarded to the
   * Python context module so it can probe authenticated endpoints.
   */
  async analyze(req: AnalyzeRequest, authSession?: AuthSession): Promise<ContextMap> {
    try {
      const payload: Record<string, unknown> = {
        url: req.url,
        params: req.params,
        waf: req.waf,
        form_method: req.formMethod ?? 'GET',
        form_fields: req.formFields ?? [],
        display_url: req.displayUrl ?? '',
      };

      // Forward cookies so the Python module can probe auth-gated endpoints
      const cookieHeader = req.cookieHeader ?? authSession?.cookieHeader;
      if (cookieHeader) {
        payload.cookie_header = cookieHeader;
        this.logger.debug(`context analyze forwarding auth cookies for ${req.url}`);
      }

      // The Python FastAPI /analyze endpoint returns AnalyzeResponse:
      //   { results: { param: { reflects_in, allowed_chars, context_confidence } },
      //     engine_version: "1.0.0",
      //     waf: "..." }
      // The Python /analyze endpoint returns the ContextMap directly,
      // NOT wrapped in { results: ... }.
      const { data } = await firstValueFrom(
        this.http.post<ContextMap>(`${this.baseUrl}/analyze`, payload),
      );
      // Support both wire formats: bare map or { results: map }
      const raw = data as Record<string, unknown>;
      const contextMap: ContextMap = (raw && typeof raw === 'object' && 'results' in raw
        ? (raw.results as unknown as ContextMap)
        : (data as ContextMap)) ?? {};
      if (!contextMap || Object.keys(contextMap).length === 0) {
        this.logger.warn(`context module returned empty results for ${req.url}`);
      } else {
        this.logger.log(`context module responded for ${req.url}: ${Object.keys(contextMap).length} params`);
      }
      return contextMap;
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
            if (typeof detailValue === 'string') detail = detailValue;
          }
        }
      }
      throw new PythonModuleException('context', detail);
    }
  }
}
import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';
import { GeneratedPayload } from './payload-client.service';
import type { AuthSession } from '../common/interfaces/auth.interface';

export interface TestRequest {
  url: string;
  payloads: GeneratedPayload[];
  verifyExecution: boolean;
  timeout: number;
  /** Stored XSS support — url becomes the store (form action) URL */
  storedMode?: boolean;
  displayUrl?: string;
  formFields?: Record<string, string>;
  /** Metadata for ML training data collection */
  context?: string;
  waf?: string;
  allowedChars?: string[];
  /**
   * When provided, the fuzzer module will inject these cookies into every
   * browser page and HTTP request it makes, enabling authenticated fuzzing.
   */
  authCookieHeader?: string;
  /** Full Playwright storageState for browser-level auth */
  authStorageState?: import('../common/interfaces/auth.interface').PlaywrightStorageState;
}

export interface FuzzResult {
  payload: string;
  target_param: string;
  reflected: boolean;
  executed: boolean;
  vuln: boolean;
  type: string;
  evidence: {
    response_code: number;
    reflection_position: string;
    browser_alert_triggered: boolean;
    exact_match?: boolean;
    sink?: string;
    source?: string;
    line?: number;
    snippet?: string;
    script_url?: string;
    severity?: string;
    confidence?: string;
    dataflow?: string;
    fragment_dependent?: boolean;
  };
}

export interface TestResponse {
  results: FuzzResult[];
}

@Injectable()
export class FuzzerClientService {
  private readonly logger = new Logger(FuzzerClientService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {
    this.baseUrl = this.config.get<string>(
      'FUZZER_URL',
      'http://localhost:5003',
    );
  }

  /**
   * Run fuzzing against `req.url`.
   * When `authSession` is provided the session cookies are forwarded to the
   * Python fuzzer module for both HTTP-level and browser-level requests.
   */
  async test(
    req: TestRequest,
    authSession?: AuthSession,
  ): Promise<TestResponse> {
    try {
      const axiosTimeoutMs = Math.max(req.timeout + 90_000, 120_000);

      const body: Record<string, unknown> = {
        url: req.url,
        payloads: req.payloads,
        verify_execution: req.verifyExecution,
        timeout: req.timeout,
        stored_mode: req.storedMode ?? false,
        display_url: req.displayUrl ?? '',
        form_fields: req.formFields ?? {},
        context: req.context ?? null,
        waf: req.waf ?? null,
        allowed_chars: req.allowedChars ?? null,
      };

      // Forward auth cookies — prefer explicit field, fall back to session
      const cookieHeader = req.authCookieHeader ?? authSession?.cookieHeader;
      if (cookieHeader) {
        body.auth_cookie_header = cookieHeader;
        this.logger.debug(`fuzzer forwarding auth cookies for ${req.url}`);
      }

      // Forward full storage state for browser-level auth
      const storageState = req.authStorageState ?? authSession?.storageState;
      if (storageState) {
        body.auth_storage_state = storageState;
      }

      const { data } = await firstValueFrom(
        this.http.post<TestResponse>(`${this.baseUrl}/test`, body, {
          timeout: axiosTimeoutMs,
        }),
      );
      this.logger.log(
        `fuzzer tested ${req.payloads.length} payloads → ${data.results.filter((r) => r.vuln).length} vulns`,
      );
      return data;
    } catch (err) {
      let detail = 'unknown';
      const errObj = err as Record<string, unknown>;
      if (typeof errObj.response === 'object' && errObj.response !== null) {
        const response = errObj.response as Record<string, unknown>;
        const responseData = response.data as Record<string, unknown>;
        if (
          typeof responseData === 'object' &&
          responseData !== null &&
          'detail' in responseData
        ) {
          detail = String(responseData.detail);
        }
      } else if (typeof errObj.message === 'string') {
        detail = errObj.message;
      }
      throw new PythonModuleException('fuzzer', detail);
    }
  }
}

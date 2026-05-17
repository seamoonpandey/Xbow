import { of, throwError } from 'rxjs';
import { ContextClientService } from './context-client.service';
import { PayloadClientService } from './payload-client.service';
import { FuzzerClientService } from './fuzzer-client.service';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';

/* ── helpers ──────────────────────────────────────────────── */

function mockConfig(overrides: Record<string, string> = {}) {
  return {
    get: jest.fn(
      (key: string, fallback?: string) => overrides[key] ?? fallback,
    ),
  } as any;
}

function mockHttp(response: any) {
  return {
    post: jest.fn(() => of({ data: response })),
    get: jest.fn(() => of({ data: response })),
  } as any;
}

function mockHttpError(msg: string) {
  return {
    post: jest.fn(() => throwError(() => new Error(msg))),
  } as any;
}

function mockHttpStatusThenResponse(status: number, response: any) {
  return {
    post: jest
      .fn()
      .mockReturnValueOnce(throwError(() => ({ response: { status } })))
      .mockReturnValueOnce(of({ data: response })),
  } as any;
}

/* ── ContextClientService ─────────────────────────────────── */

describe('ContextClientService', () => {
  it('calls POST /analyze and returns context map', async () => {
    const resp = {
      q: {
        reflects_in: 'html_text',
        allowed_chars: ['<', '>'],
        context_confidence: 0.9,
      },
    };
    const http = mockHttp(resp);
    const svc = new ContextClientService(http, mockConfig());
    const result = await svc.analyze({
      url: 'https://t.com',
      params: ['q'],
      waf: 'none',
    });
    expect(http.post).toHaveBeenCalledWith(
      'http://localhost:5001/analyze',
      expect.anything(),
    );
    // Verify the new canonical fields are always sent with defaults
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.form_method).toBe('GET');
    expect(postBody.form_fields).toEqual([]);
    expect(postBody.display_url).toBe('');
    expect(result.q.reflects_in).toBe('html_text');
  });

  it('forwards form_method, form_fields, display_url, and cookie_header', async () => {
    const http = mockHttp({});
    const svc = new ContextClientService(http, mockConfig());
    await svc.analyze({
      url: 'https://t.com/form',
      params: ['field1', 'field2'],
      waf: 'cloudflare',
      formMethod: 'POST',
      formFields: ['field1', 'field2'],
      displayUrl: 'https://t.com/display',
      cookieHeader: 'session=abc123',
    });
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.form_method).toBe('POST');
    expect(postBody.form_fields).toEqual(['field1', 'field2']);
    expect(postBody.display_url).toBe('https://t.com/display');
    expect(postBody.cookie_header).toBe('session=abc123');
  });

  it('uses configured CONTEXT_URL', async () => {
    const http = mockHttp({});
    const svc = new ContextClientService(
      http,
      mockConfig({ CONTEXT_URL: 'http://ctx:9000' }),
    );
    await svc.analyze({ url: 'https://t.com', params: ['q'], waf: 'none' });
    expect(http.post).toHaveBeenCalledWith(
      'http://ctx:9000/analyze',
      expect.anything(),
    );
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('network fail');
    const svc = new ContextClientService(http, mockConfig());
    await expect(
      svc.analyze({ url: 'https://t.com', params: ['q'], waf: 'none' }),
    ).rejects.toThrow(PythonModuleException);
  });
});

/* ── PayloadClientService ─────────────────────────────────── */

describe('PayloadClientService', () => {
  it('calls POST /generate and returns payloads', async () => {
    const resp = {
      payloads: [
        {
          payload: '<img src=x>',
          target_param: 'q',
          context: 'html_text',
          confidence: 0.8,
          waf_bypass: false,
        },
      ],
    };
    const http = mockHttp(resp);
    const svc = new PayloadClientService(http, mockConfig());
    const result = await svc.generate({
      contexts: {},
      waf: 'none',
      maxPayloads: 10,
    });
    expect(http.post).toHaveBeenCalledWith(
      'http://localhost:5002/generate',
      expect.objectContaining({ max_payloads: 10 }),
    );
    expect(result.payloads).toHaveLength(1);
  });

  it('remaps maxPayloads to max_payloads for Python API', async () => {
    const http = mockHttp({ payloads: [] });
    const svc = new PayloadClientService(http, mockConfig());
    await svc.generate({ contexts: {}, waf: 'none', maxPayloads: 25 });
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.max_payloads).toBe(25);
    expect(postBody.maxPayloads).toBeUndefined();
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('timeout');
    const svc = new PayloadClientService(http, mockConfig());
    await expect(
      svc.generate({ contexts: {}, waf: 'none', maxPayloads: 10 }),
    ).rejects.toThrow(PythonModuleException);
  });
});

/* ── FuzzerClientService ──────────────────────────────────── */

describe('FuzzerClientService', () => {
  it('calls POST /fuzz and returns results', async () => {
    const resp = {
      results: [
        {
          payload: '<script>',
          target_param: 'q',
          reflected: true,
          executed: false,
          vuln: false,
          type: '',
          evidence: {},
        },
      ],
    };
    const http = mockHttp(resp);
    const svc = new FuzzerClientService(http, mockConfig());
    const result = await svc.test({
      url: 'https://t.com',
      payloads: [],
      verifyExecution: true,
      timeout: 5000,
    });
    expect(http.post).toHaveBeenCalledWith(
      'http://localhost:5003/fuzz',
      expect.objectContaining({ verify_execution: true }),
      expect.objectContaining({ timeout: 120000 }),
    );
    expect(result.results).toHaveLength(1);
  });

  it('falls back to legacy POST /test when /fuzz is missing', async () => {
    const resp = { results: [] };
    const http = mockHttpStatusThenResponse(404, resp);
    const svc = new FuzzerClientService(http, mockConfig());
    const result = await svc.test({
      url: 'https://t.com',
      payloads: [],
      verifyExecution: true,
      timeout: 5000,
    });
    expect(http.post).toHaveBeenNthCalledWith(
      1,
      'http://localhost:5003/fuzz',
      expect.objectContaining({ verify_execution: true }),
      expect.objectContaining({ timeout: 120000 }),
    );
    expect(http.post).toHaveBeenNthCalledWith(
      2,
      'http://localhost:5003/test',
      expect.objectContaining({ verify_execution: true }),
      expect.objectContaining({ timeout: 120000 }),
    );
    expect(result.results).toHaveLength(0);
  });

  it('remaps verifyExecution to verify_execution for Python API', async () => {
    const http = mockHttp({ results: [] });
    const svc = new FuzzerClientService(http, mockConfig());
    await svc.test({
      url: 'https://t.com',
      payloads: [],
      verifyExecution: false,
      timeout: 3000,
    });
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.verify_execution).toBe(false);
  });

  it('forwards auth cookies and storage state to Python API', async () => {
    const http = mockHttp({ results: [] });
    const svc = new FuzzerClientService(http, mockConfig());
    const storageState = {
      cookies: [
        {
          name: 'session',
          value: 'tok123',
          domain: 't.com',
          path: '/',
          expires: -1,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
        },
      ],
      origins: [],
    } as any;
    await svc.test(
      {
        url: 'https://t.com',
        payloads: [],
        verifyExecution: true,
        timeout: 3000,
      },
      {
        cookieHeader: 'session=tok123',
        storageState,
        createdAt: new Date(),
      },
    );
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.auth_cookie_header).toBe('session=tok123');
    expect(postBody.auth_storage_state).toBe(storageState);
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('connection refused');
    const svc = new FuzzerClientService(http, mockConfig());
    await expect(
      svc.test({
        url: 'https://t.com',
        payloads: [],
        verifyExecution: true,
        timeout: 5000,
      }),
    ).rejects.toThrow(PythonModuleException);
  });
});

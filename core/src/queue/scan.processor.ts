import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { ScanService } from '../scan/scan.service';
import { ScanGateway } from '../scan/scan.gateway';
import { CrawlerService } from '../crawler/crawler.service';
import { ContextClientService } from '../modules-bridge/context-client.service';
import {
  PayloadClientService,
  GeneratedPayload,
} from '../modules-bridge/payload-client.service';
import { FuzzerClientService } from '../modules-bridge/fuzzer-client.service';
import { ReportService } from '../report/report.service';
import { AuthService } from '../userauth/auth.service';
import { ScannerLogService } from '../scanner-log/scanner-log.service';
import {
  ScanStatus,
  ScanPhase,
  ScanRecord,
} from '../common/interfaces/scan.interface';
import type { AuthSession } from '../common/interfaces/auth.interface';
import { SCAN_QUEUE } from './scan.producer';

const SCAN_WORKER_CONCURRENCY = Math.max(
  1,
  Number(process.env.SCAN_WORKER_CONCURRENCY ?? 2),
);

/** Template-breakout payloads for __fragment__ auto-discovery.
 *  These handle scenarios where the fragment value is concatenated into
 *  an existing HTML template before DOM injection (e.g.
 *  `jQuery.html('<tag>' + location.hash + '</tag>')`). Generic html_body
 *  payloads (<script>…) land inside the quoted attribute and never execute. */
const FRAGMENT_BREAKOUT_PAYLOADS: GeneratedPayload[] = [
  { payload: "1' onerror='alert(1)", target_param: '__fragment__', context: 'attribute', confidence: 0.85, waf_bypass: false, technique: 'template_breakout', severity: 'high' },
  { payload: '1" onerror="alert(1)', target_param: '__fragment__', context: 'attribute', confidence: 0.85, waf_bypass: false, technique: 'template_breakout', severity: 'high' },
  { payload: "1'><img src=x onerror=alert(1)>", target_param: '__fragment__', context: 'attribute', confidence: 0.8, waf_bypass: false, technique: 'template_breakout', severity: 'high' },
  { payload: '1"><img src=x onerror=alert(1)>', target_param: '__fragment__', context: 'attribute', confidence: 0.8, waf_bypass: false, technique: 'template_breakout', severity: 'high' },
  { payload: "1' autofocus onfocus='alert(1)", target_param: '__fragment__', context: 'attribute', confidence: 0.75, waf_bypass: false, technique: 'template_breakout', severity: 'medium' },
  { payload: '1" autofocus onfocus="alert(1)', target_param: '__fragment__', context: 'attribute', confidence: 0.75, waf_bypass: false, technique: 'template_breakout', severity: 'medium' },
  { payload: '1 onmouseover=alert(1) //', target_param: '__fragment__', context: 'attribute', confidence: 0.7, waf_bypass: false, technique: 'template_breakout', severity: 'medium' },
];

function canonicalizeTargetUrl(
  rawUrl: string,
  baseUrl?: string,
): { url: string; params: string[] } {
  try {
    const u = baseUrl ? new URL(rawUrl, baseUrl) : new URL(rawUrl);
    const paramNames = [...new Set([...u.searchParams.keys()])].sort();
    const canonicalSearch =
      paramNames.length > 0
        ? `?${paramNames.map((p) => `${encodeURIComponent(p)}=`).join('&')}`
        : '';
    const canonicalUrl = `${u.origin}${u.pathname}${canonicalSearch}`;
    return { url: canonicalUrl, params: paramNames };
  } catch {
    return { url: rawUrl, params: [] };
  }
}

@Processor(SCAN_QUEUE, { concurrency: SCAN_WORKER_CONCURRENCY })
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    private readonly scanService: ScanService,
    private readonly gateway: ScanGateway,
    private readonly crawlerService: CrawlerService,
    private readonly contextClient: ContextClientService,
    private readonly payloadClient: PayloadClientService,
    private readonly fuzzerClient: FuzzerClientService,
    private readonly reportService: ReportService,
    private readonly authService: AuthService,
    private readonly scannerLog: ScannerLogService,
  ) {
    super();
  }

  private extractPostId(url: string): string | null {
    try {
      const u = new URL(url);
      for (const key of [
        'postId',
        'post_id',
        'id',
        'articleId',
        'article_id',
      ]) {
        const val = u.searchParams.get(key);
        if (val) return val;
      }
    } catch {
      /* ignore */
    }
    return null;
  }

  async process(job: Job<{ scanId: string }>): Promise<void> {
    const { scanId } = job.data;
    const startedAt = Date.now();

    try {
      let scan: ScanRecord;
      try {
        scan = await this.scanService.findOne(scanId);
      } catch (err) {
        const detail = err instanceof Error ? err.message : 'scan not found';
        this.logger.warn(
          `skipping scan job for missing scanId=${scanId}: ${detail}`,
        );
        return;
      }

      // ── Phase 0: AUTHENTICATION (optional) ──────────────────────────
      let authSession: AuthSession | undefined;

      if (scan.options.auth?.enabled) {
        const authStartedAt = Date.now();
        await this.scanService.updateStatus(
          scanId,
          ScanStatus.CRAWLING,
          ScanPhase.AUTH,
          2,
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.AUTH,
          progress: 2,
          message: `authenticating at ${scan.options.auth.loginUrl}`,
        });

        const authResult = await this.authService.login(scan.options.auth);

        if (!authResult.success) {
          this.logger.error(
            `authentication failed for scanId=${scanId}: ${authResult.error}`,
          );
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.AUTH,
            progress: 4,
            message: `⚠ auth failed (${authResult.error}) — continuing unauthenticated`,
          });
          this.logger.warn(
            `scan ${scanId} falling back to unauthenticated mode`,
          );
          await this.scanService.addAuditLog(
            scanId,
            'AUTH',
            `Authentication failed at ${scan.options.auth.loginUrl}: ${authResult.error}`,
            {
              loginUrl: scan.options.auth.loginUrl,
              error: authResult.error,
            },
            Date.now() - authStartedAt,
          );
        } else {
          authSession = authResult.session;
          this.scannerLog.append(scanId, {
            timestamp: new Date().toISOString(),
            phase: 'AUTH',
            message: `Login successful at ${scan.options.auth.loginUrl}, ${authSession.storageState.cookies.length} cookies captured`,
            durationMs: Date.now() - authStartedAt,
          });
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.AUTH,
            progress: 4,
            message: `authenticated — session captured (${authSession.storageState.cookies.length} cookies)`,
          });
          this.logger.log(
            `scan ${scanId} authenticated successfully, proceeding with session`,
          );
          await this.scanService.addAuditLog(
            scanId,
            'AUTH',
            `Login successful at ${scan.options.auth.loginUrl}`,
            {
              loginUrl: scan.options.auth.loginUrl,
              cookiesCaptured: authSession.storageState.cookies.length,
            },
            Date.now() - authStartedAt,
          );
        }
      }

      // ── Phase 1: CRAWL ───────────────────────────────────────────────
      const crawlStartedAt = Date.now();
      this.scannerLog.append(scanId, {
        timestamp: new Date().toISOString(),
        phase: 'CRAWL',
        message: 'Starting crawl phase',
        durationMs: 0,
      });
      await this.scanService.updateStatus(
        scanId,
        ScanStatus.CRAWLING,
        ScanPhase.CRAWL,
        5,
      );
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 5,
        message: scan.options.singlePage
          ? 'single-page mode — skipping crawl'
          : `crawling target${authSession ? ' (authenticated)' : ''}, discovering params`,
      });

      const urlParamsMap = new Map<string, string[]>();
      let waf = 'none';
      let crawledForms: import('../common/interfaces/crawler.interface').DiscoveredForm[] =
        [];
      let allCrawledUrls: string[] = [];

      if (scan.options.singlePage) {
        const { url: canonicalRoot, params: rootParams } =
          canonicalizeTargetUrl(scan.url);
        urlParamsMap.set(canonicalRoot, rootParams);
        allCrawledUrls = [canonicalRoot];
      } else {
        const crawlResult = await this.crawlerService.crawl(
          scan.url,
          scan.options.depth ?? 3,
          scan.options.maxParams ?? 100,
          authSession,
        );

        waf = crawlResult.waf.name ?? 'none';
        crawledForms = crawlResult.forms;
        allCrawledUrls = crawlResult.urls.map(
          (u) => canonicalizeTargetUrl(u).url,
        );

        for (const crawledUrl of crawlResult.urls) {
          const { url: canonicalUrl, params } =
            canonicalizeTargetUrl(crawledUrl);
          const existing = urlParamsMap.get(canonicalUrl) ?? [];
          urlParamsMap.set(canonicalUrl, [
            ...new Set([...existing, ...params]),
          ]);
        }

        for (const form of crawlResult.forms) {
          if (form.action && form.fields.length > 0) {
            const { url: canonicalUrl, params } = canonicalizeTargetUrl(
              form.action,
              scan.url,
            );
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, ...params, ...form.fields]),
            ]);
          }
        }

        for (const param of crawlResult.params) {
          if (param.source === 'form' && param.formAction) {
            const { url: canonicalUrl, params: existingUrlParams } =
              canonicalizeTargetUrl(param.formAction, scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, ...existingUrlParams, param.name]),
            ]);
          } else if (param.source === 'form' && !param.formAction) {
            const { url: canonicalUrl } = canonicalizeTargetUrl(scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, param.name]),
            ]);
          } else if (param.source === 'fragment') {
            const { url: canonicalUrl } = canonicalizeTargetUrl(scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, param.name]),
            ]);
          } else if (param.source === 'query') {
            const { url: canonicalUrl } = canonicalizeTargetUrl(scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, param.name]),
            ]);
          }
        }

        try {
          const { url: canonicalRoot, params: rootParams } =
            canonicalizeTargetUrl(scan.url);
          if (rootParams.length > 0 && !urlParamsMap.has(canonicalRoot)) {
            urlParamsMap.set(canonicalRoot, rootParams);
          }
        } catch {
          // skip
        }
      }

      const targetEntries = Array.from(urlParamsMap.entries());
      const totalUniqueParams = new Set(
        targetEntries.flatMap(([, params]) => params),
      ).size;

      this.scannerLog.append(scanId, {
        timestamp: new Date().toISOString(),
        phase: 'CRAWL',
        message: `Crawled ${allCrawledUrls.length} URLs, ${totalUniqueParams} params, WAF: ${waf}, forms: ${crawledForms.length}`,
        details: {
          totalUrls: allCrawledUrls.length,
          totalParams: totalUniqueParams,
          waf,
          forms: crawledForms.length,
        },
        durationMs: Date.now() - crawlStartedAt,
      });

      await this.scanService.addAuditLog(
        scanId,
        'CRAWL',
        `Crawled target and discovered ${allCrawledUrls.length} URLs with ${totalUniqueParams} unique params`,
        {
          totalUrls: allCrawledUrls.length,
          totalParams: totalUniqueParams,
          totalTargets: targetEntries.length,
          formsFound: crawledForms.length,
          wafDetected: waf,
          urls: allCrawledUrls.slice(0, 50),
        },
        Date.now() - crawlStartedAt,
      );

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 20,
        message: `found ${totalUniqueParams} params across ${targetEntries.length} url(s)${
          waf !== 'none' ? `, waf: ${waf}` : ''
        }${authSession ? ' [authenticated]' : ''}`,
      });

      if (targetEntries.length === 0) {
        this.logger.warn(`no parameterized URLs found for scanId=${scanId}`);
        await this.scanService.updateStatus(
          scanId,
          ScanStatus.DONE,
          ScanPhase.REPORT,
          100,
        );
        this.gateway.emitComplete({
          scanId,
          summary: {
            totalParams: 0,
            paramsTested: 0,
            vulnsFound: 0,
            durationMs: Date.now() - startedAt,
          },
          reportUrl: '',
        });
        return;
      }

      // ── Per-URL pipeline: CONTEXT → PAYLOAD-GEN → FUZZ ──────────────
      // ── Per-URL listing ────────────────────────────────────────────
      this.scannerLog.append(scanId, {
        timestamp: new Date().toISOString(),
        phase: 'CRAWL',
        message: `URLs discovered: ${targetEntries.length} target(s), ${allCrawledUrls.length} total URLs crawled`,
        details: {
          targets: targetEntries.map(([url, params]) => ({
            url,
            paramCount: params.length,
            params,
          })),
          forms: crawledForms.map((f) => ({
            sourceUrl: f.sourceUrl,
            action: f.action,
            method: f.method,
            fields: f.fields,
          })),
          allUrls: allCrawledUrls.slice(0, 200),
        },
        durationMs: 0,
      });

      await this.scanService.updateStatus(
        scanId,
        ScanStatus.ANALYZING,
        ScanPhase.CONTEXT,
        25,
      );

      let totalPayloadsTested = 0;
      let totalVulnsFound = 0;
      const totalTargets = targetEntries.length;

      const auditPayloadsByUrl: Record<
        string,
        { params: string[]; payloads: string[] }
      > = {};
      const auditInjectionPoints: {
        url: string;
        param: string;
        method: string;
      }[] = [];

      for (let i = 0; i < totalTargets; i++) {
        const [targetUrl, targetParams] = targetEntries[i];
        const urlStartedAt = Date.now();

        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'CONTEXT',
          message: `[${i + 1}/${totalTargets}] Processing URL: ${targetUrl}`,
          details: {
            url: targetUrl,
            params: targetParams,
            urlIndex: i,
            totalUrls: totalTargets,
          },
          durationMs: 0,
        });

        const pct = (n: number) =>
          Math.round(25 + ((i + n) / totalTargets) * 60);

        this.logger.log(
          `[${i + 1}/${totalTargets}] processing ${targetUrl} (${targetParams.length} params)${
            authSession ? ' [auth]' : ''
          }`,
        );

        for (const param of targetParams) {
          auditInjectionPoints.push({
            url: targetUrl,
            param,
            method: 'URLSearchParams',
          });
        }

        if (targetParams.length === 0) {
          await this.scanService.updateStatus(
            scanId,
            ScanStatus.FUZZING,
            ScanPhase.FUZZ,
            pct(0.5),
          );
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(0.5),
            message: `[${i + 1}/${totalTargets}] dom-only scanning ${targetUrl}`,
          });

          let urlVulnCount = 0;
          let domVulns: import('../modules-bridge/fuzzer-client.service').FuzzResult[] =
            [];
          try {
            const domResp = await this.fuzzerClient.test(
              {
                url: targetUrl,
                payloads: [],
                verifyExecution: false,
                timeout: scan.options.timeout ?? 60000,
              },
              authSession,
            );
            domVulns = domResp.results.filter((r) => r.vuln);
            for (const r of domVulns) {
              const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
              if (await this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
                urlVulnCount++;
              }
            }
            totalVulnsFound += domVulns.length;
          } catch (err) {
            const detail = err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(
              `dom-only scan failed for ${targetUrl}: ${detail}, skipping`,
            );
          }

          // ── Fragment auto-discovery from DOM findings ──────────────
          // When the DOM-only scan finds fragment-based XSS (evidence marks
          // fragment_dependent = true), auto-generate __fragment__ payloads
          // and dynamically verify them in the headless browser.
          const fragmentDomVulns = domVulns.filter(
            (r) => r.evidence?.fragment_dependent === true,
          );

          if (fragmentDomVulns.length > 0) {
            const FRAGMENT_CHARS = [
              '<',
              '>',
              '"',
              "'",
              '/',
              '(',
              ')',
              ';',
              '=',
              '#',
              ':',
            ];

            this.logger.log(
              `fragment DOM XSS: ${fragmentDomVulns.length} findings on ${targetUrl}, generating fragment payloads`,
            );

            const fragmentContexts: Record<
              string,
              {
                reflects_in: string;
                allowed_chars: string[];
                context_confidence: number;
              }
            > = {
              __fragment__: {
                reflects_in: 'attribute',
                allowed_chars: FRAGMENT_CHARS,
                context_confidence: 0.75,
              },
            };

            let fragmentPayloads: GeneratedPayload[] = [];
            try {
              const genResp = await this.payloadClient.generate({
                contexts: fragmentContexts,
                waf,
                maxPayloads: scan.options.maxPayloadsPerParam ?? 50,
              });
              fragmentPayloads = genResp.payloads;
            } catch (err) {
              const detail =
                err instanceof Error ? err.message : 'payload-gen error';
              this.logger.warn(
                `fragment payload-gen failed for ${targetUrl}: ${detail}`,
              );
            }

            // Inject template-breakout payloads for scenarios where the
            // fragment value is concatenated into an existing HTML template
            // before DOM injection (e.g. jQuery.html('<tag>' + frag + '</tag>')).
            // Generic fragment payloads assume direct innerHTML assignment,
            // but real apps often wrap the hash in a template first.
            fragmentPayloads = [...FRAGMENT_BREAKOUT_PAYLOADS, ...fragmentPayloads];
            this.logger.log(
              `fragment payloads: ${fragmentPayloads.length} total (${FRAGMENT_BREAKOUT_PAYLOADS.length} template-breakout + ${fragmentPayloads.length - FRAGMENT_BREAKOUT_PAYLOADS.length} generic) for ${targetUrl}`,
            );

            if (fragmentPayloads.length > 0) {
              this.gateway.emitProgress({
                scanId,
                phase: ScanPhase.FUZZ,
                progress: pct(0.95),
                message: `[${i + 1}/${totalTargets}] testing ${fragmentPayloads.length} fragment payloads on ${targetUrl}`,
              });

              try {
                const fragResp = await this.fuzzerClient.test(
                  {
                    url: targetUrl,
                    payloads: fragmentPayloads,
                    verifyExecution: scan.options.verifyExecution ?? true,
                    timeout: scan.options.timeout ?? 60000,
                    context: 'attribute',
                    waf,
                    allowedChars: FRAGMENT_CHARS,
                  },
                  authSession,
                );

                const confirmedFragVulns = fragResp.results.filter(
                  (r) => r.vuln,
                );
                totalPayloadsTested += fragmentPayloads.length;

                for (const r of confirmedFragVulns) {
                  const vuln = this.reportService.buildVuln(
                    scanId,
                    targetUrl,
                    r,
                  );
                  if (await this.scanService.addVuln(scanId, vuln)) {
                    this.gateway.emitFinding({ scanId, vuln });
                  }
                }
                totalVulnsFound += confirmedFragVulns.length;

                this.logger.log(
                  `fragment XSS: ${confirmedFragVulns.length}/${fragmentPayloads.length} vulns confirmed on ${targetUrl}`,
                );
              } catch (err) {
                const detail =
                  err instanceof Error ? err.message : 'fuzzer error';
                this.logger.warn(
                  `fragment fuzzing failed for ${targetUrl}: ${detail}`,
                );
              }
            }
          }

          const urlDurationMs = Date.now() - urlStartedAt;
          this.scannerLog.append(scanId, {
            timestamp: new Date().toISOString(),
            phase: 'FUZZ',
            message: `URL ${i + 1}/${totalTargets} done: ${targetUrl} (DOM-only, ${urlVulnCount} vulns)`,
            details: {
              url: targetUrl,
              urlIndex: i,
              totalUrls: totalTargets,
              urlDurationMs,
              payloadsTested: 0,
              vulnsFound: urlVulnCount,
              mode: 'dom-only',
            },
            durationMs: urlDurationMs,
          });

          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(1),
            message: `[${i + 1}/${totalTargets}] dom-only done (${totalVulnsFound} total)`,
          });
          continue;
        }

        // ── CONTEXT for this URL ────────────────────────────────────
        const contextStartedAt = Date.now();
        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'CONTEXT',
          message: `Analyzing ${targetUrl} (${targetParams.length} params)`,
          details: { url: targetUrl, params: targetParams },
          durationMs: 0,
        });
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.CONTEXT,
          progress: pct(0),
          message: `[${i + 1}/${totalTargets}] analyzing ${targetUrl}`,
        });

        let contexts;
        try {
          contexts = await this.contextClient.analyze(
            { url: targetUrl, params: targetParams, waf },
            authSession,
          );
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'context module error';
          this.logger.warn(
            `context failed for ${targetUrl}: ${detail}, skipping`,
          );
          await this.scanService.addAuditLog(
            scanId,
            'CONTEXT',
            `Context analysis failed for ${targetUrl}: ${detail}`,
            {
              url: targetUrl,
              params: targetParams,
              error: detail,
            },
            Date.now() - contextStartedAt,
          );
          continue;
        }

        await this.scanService.addAuditLog(
          scanId,
          'CONTEXT',
          `Context analyzed for ${targetUrl}, found ${Object.keys(contexts).length} contexts`,
          {
            url: targetUrl,
            contextsCount: Object.keys(contexts).length,
            contexts,
          },
          Date.now() - contextStartedAt,
        );

        // Fragment param synthetic context injection
        const FRAGMENT_PARAM = '__fragment__';
        const DEFAULT_FRAGMENT_CHARS = [
          '<',
          '>',
          '"',
          "'",
          '/',
          '(',
          ')',
          ';',
          '=',
          '#',
          ':',
        ];
        for (const [paramName, ctx] of Object.entries(contexts)) {
          const ctxObj = ctx as { reflects_in: string };
          // The context module can never detect fragment reflection (server never
          // sees the hash), so always upgrade __fragment__ to 'attribute' context.
          // This ensures payload-gen targets attribute-breakout payloads instead
          // of html_body payloads that can't exploit template-wrap scenarios.
          if (paramName === FRAGMENT_PARAM) {
            (ctx as Record<string, unknown>).reflects_in = 'attribute';
            (ctx as Record<string, unknown>).allowed_chars =
              DEFAULT_FRAGMENT_CHARS;
            (ctx as Record<string, unknown>).context_confidence = 0.85;
          }
        }

        const reflectedParams = Object.entries(contexts).filter(
          ([, ctx]) => (ctx as { reflects_in: string }).reflects_in !== 'none',
        );

        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'CONTEXT',
          message: `Context analyzed for ${targetUrl}: ${reflectedParams.length} reflecting contexts`,
          details: {
            url: targetUrl,
            contextsCount: Object.keys(contexts).length,
            reflectingParams: reflectedParams.length,
          },
          durationMs: Date.now() - contextStartedAt,
        });

        if (reflectedParams.length === 0) {
          // ── Fallback: synthesize contexts for params that didn't reflect ──
          const defaultChars = [
            '<',
            '>',
            '"',
            "'",
            '/',
            '(',
            ')',
            ';',
            '=',
            '#',
            ':',
          ];
          const syntheticContexts: Record<
            string,
            {
              reflects_in: string;
              allowed_chars: string[];
              context_confidence: number;
            }
          > = {};
          let fallbackVulnsCount = 0;
          let fallbackDomVulnsCount = 0;
          for (const param of targetParams) {
            syntheticContexts[param] = {
              reflects_in: 'html_body',
              allowed_chars: defaultChars,
              context_confidence: 0.5,
            };
          }

          this.logger.log(
            `no reflecting params found for ${targetUrl}, synthesizing ${targetParams.length} contexts for fallback fuzzing`,
          );
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.PAYLOAD_GEN,
            progress: pct(0.33),
            message: `[${i + 1}/${totalTargets}] fallback: generating payloads for ${targetUrl}`,
          });

          let fallbackPayloads;
          try {
            const genResp = await this.payloadClient.generate({
              contexts: syntheticContexts,
              waf,
              maxPayloads: scan.options.maxPayloadsPerParam ?? 50,
            });
            fallbackPayloads = genResp.payloads;
          } catch (err) {
            const detail =
              err instanceof Error ? err.message : 'payload-gen error';
            this.logger.warn(
              `fallback payload-gen failed for ${targetUrl}: ${detail}`,
            );
            fallbackPayloads = [];
          }

          const maxPerParam = scan.options.maxPayloadsPerParam ?? 50;
          const perParam = new Map<string, Set<string>>();
          const uniqueFallback: typeof fallbackPayloads = [];
          for (const p of fallbackPayloads ?? []) {
            const paramKey = String(p.target_param ?? '');
            if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
            const seen = perParam.get(paramKey)!;
            if (seen.has(p.payload)) continue;
            if (seen.size >= maxPerParam) continue;
            seen.add(p.payload);
            uniqueFallback.push(p);
          }

          await this.scanService.addAuditLog(
            scanId,
            'CONTEXT',
            `Fallback contexts synthesized for ${targetUrl}: ${uniqueFallback.length} fallback payloads`,
            {
              url: targetUrl,
              params: targetParams,
              fallbackPayloads: uniqueFallback.length,
            },
            Date.now() - contextStartedAt,
          );

          // ── Inject template-breakout payloads for __fragment__ in fallback ──
          if (targetParams.includes('__fragment__')) {
            const existing = new Set(uniqueFallback.map(p => `${p.target_param}:${p.payload}`));
            const toInject = FRAGMENT_BREAKOUT_PAYLOADS.filter(bp => !existing.has(`${bp.target_param}:${bp.payload}`));
            uniqueFallback.unshift(...toInject);
            this.logger.log(
              `fragment fallback: injected ${toInject.length} template-breakout payloads for ${targetUrl}`,
            );
          }

          if (uniqueFallback.length > 0) {
            auditPayloadsByUrl[targetUrl] = {
              params: targetParams,
              payloads: uniqueFallback.map(
                (p) => `${p.target_param}=${p.payload}`,
              ),
            };

            this.scannerLog.append(scanId, {
              timestamp: new Date().toISOString(),
              phase: 'PAYLOAD_GEN',
              message: `Fallback: generated ${uniqueFallback.length} payloads for ${targetUrl}`,
              details: { url: targetUrl, totalPayloads: uniqueFallback.length },
              durationMs: Date.now() - contextStartedAt,
            });

            await this.scanService.updateStatus(
              scanId,
              ScanStatus.FUZZING,
              ScanPhase.FUZZ,
              pct(0.66),
            );
            this.gateway.emitProgress({
              scanId,
              phase: ScanPhase.FUZZ,
              progress: pct(0.66),
              message: `[${i + 1}/${totalTargets}] fuzzing ${targetUrl} with ${uniqueFallback.length} fallback payloads`,
            });

            try {
              const fuzzResp = await this.fuzzerClient.test(
                {
                  url: targetUrl,
                  payloads: uniqueFallback,
                  verifyExecution: scan.options.verifyExecution ?? true,
                  timeout: scan.options.timeout ?? 60000,
                  context: 'html_body',
                  waf,
                  allowedChars: defaultChars,
                },
                authSession,
              );
              const fuzzVulns = fuzzResp.results.filter((r) => r.vuln);
              fallbackVulnsCount = fuzzVulns.length;
              totalPayloadsTested += uniqueFallback.length;
              for (const r of fuzzVulns) {
                const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
                if (await this.scanService.addVuln(scanId, vuln)) {
                  this.gateway.emitFinding({ scanId, vuln });
                }
              }
              totalVulnsFound += fuzzVulns.length;

              this.scannerLog.append(scanId, {
                timestamp: new Date().toISOString(),
                phase: 'FUZZ',
                message: `Fallback fuzzing: ${fuzzVulns.length} vulns on ${targetUrl}`,
                details: {
                  url: targetUrl,
                  payloadsTested: uniqueFallback.length,
                  vulnsFound: fuzzVulns.length,
                },
                durationMs: Date.now() - contextStartedAt,
              });
            } catch (err) {
              const detail =
                err instanceof Error ? err.message : 'fuzzer error';
              this.logger.warn(
                `fallback fuzzing failed for ${targetUrl}: ${detail}, falling back to DOM-only`,
              );
            }
          }

          // Always run DOM-only scan
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(0.8),
            message: `[${i + 1}/${totalTargets}] dom-only scanning ${targetUrl}`,
          });

          try {
            const domResp = await this.fuzzerClient.test(
              {
                url: targetUrl,
                payloads: [],
                verifyExecution: false,
                timeout: scan.options.timeout ?? 60000,
              },
              authSession,
            );
            const domVulns = domResp.results.filter((r) => r.vuln);
            fallbackDomVulnsCount = domVulns.length;
            for (const r of domVulns) {
              const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
              if (await this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
              }
            }
            totalVulnsFound += domVulns.length;
          } catch (err) {
            const detail = err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(
              `dom-only scan failed for ${targetUrl}: ${detail}, skipping`,
            );
          }

          const totalUrlVulns = fallbackVulnsCount + fallbackDomVulnsCount;
          const fallbackUrlDurationMs = Date.now() - urlStartedAt;
          this.scannerLog.append(scanId, {
            timestamp: new Date().toISOString(),
            phase: 'FUZZ',
            message: `URL ${i + 1}/${totalTargets} done: ${targetUrl} (${totalUrlVulns} vulns)`,
            details: {
              url: targetUrl,
              params: targetParams,
              urlIndex: i,
              totalUrls: totalTargets,
              urlDurationMs: fallbackUrlDurationMs,
              payloadsTested: uniqueFallback.length,
              vulnsFound: totalUrlVulns,
              mode: 'fallback',
            },
            durationMs: fallbackUrlDurationMs,
          });

          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(1),
            message: `[${i + 1}/${totalTargets}] done (${totalVulnsFound} total vulns)`,
          });
          continue;
        }

        this.logger.log(
          `${reflectedParams.length} reflecting params on ${targetUrl}`,
        );

        // ── PAYLOAD-GEN for this URL ────────────────────────────────
        const payloadGenStartedAt = Date.now();
        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'PAYLOAD_GEN',
          message: `Generating payloads for ${targetUrl}`,
          details: { url: targetUrl, reflectingParams: reflectedParams.length },
          durationMs: 0,
        });
        await this.scanService.updateStatus(
          scanId,
          ScanStatus.GENERATING,
          ScanPhase.PAYLOAD_GEN,
          pct(0.33),
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.PAYLOAD_GEN,
          progress: pct(0.33),
          message: `[${i + 1}/${totalTargets}] generating payloads for ${targetUrl}`,
        });

        let payloads;
        try {
          const genResp = await this.payloadClient.generate({
            contexts,
            waf,
            maxPayloads: scan.options.maxPayloadsPerParam ?? 100,
          });
          payloads = genResp.payloads;
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'payload-gen error';
          this.logger.warn(
            `payload-gen failed for ${targetUrl}: ${detail}, skipping`,
          );
          await this.scanService.addAuditLog(
            scanId,
            'PAYLOAD_GEN',
            `Payload generation failed for ${targetUrl}: ${detail}`,
            {
              url: targetUrl,
              params: targetParams,
              error: detail,
            },
            Date.now() - payloadGenStartedAt,
          );
          continue;
        }

        if (payloads.length === 0) continue;

        // Deduplicate payloads
        const maxPerParam = scan.options.maxPayloadsPerParam ?? 100;
        const perParam = new Map<string, Set<string>>();
        const uniquePayloads: typeof payloads = [];
        for (const p of payloads) {
          const paramKey = String(p.target_param ?? '');
          if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
          const seen = perParam.get(paramKey)!;
          if (seen.has(p.payload)) continue;
          if (seen.size >= maxPerParam) continue;
          seen.add(p.payload);
          uniquePayloads.push(p);
        }

        auditPayloadsByUrl[targetUrl] = {
          params: targetParams,
          payloads: uniquePayloads.map((p) => `${p.target_param}=${p.payload}`),
        };

        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'PAYLOAD_GEN',
          message: `Generated ${uniquePayloads.length} unique payloads for ${targetUrl}`,
          details: {
            url: targetUrl,
            totalPayloads: payloads.length,
            uniquePayloads: uniquePayloads.length,
          },
          durationMs: Date.now() - payloadGenStartedAt,
        });

        await this.scanService.addAuditLog(
          scanId,
          'PAYLOAD_GEN',
          `Generated ${uniquePayloads.length} unique payloads for ${targetUrl} (${targetParams.length} params)`,
          {
            url: targetUrl,
            params: targetParams,
            totalPayloads: payloads.length,
            uniquePayloads: uniquePayloads.length,
            payloadSamples: uniquePayloads
              .slice(0, 10)
              .map((p) => ({ param: p.target_param, payload: p.payload })),
          },
          Date.now() - payloadGenStartedAt,
        );

        // ── Inject template-breakout payloads for __fragment__ ─────
        // When __fragment__ is a discovered param, prepend breakout payloads
        // designed for template-wrap scenarios (e.g. `attr="prefix"+hash+"suffix"`)
        // that generic html_body payloads cannot exploit.
        if (targetParams.includes('__fragment__')) {
          const existing = new Set(uniquePayloads.map(p => `${p.target_param}:${p.payload}`));
          const toInject = FRAGMENT_BREAKOUT_PAYLOADS.filter(bp => !existing.has(`${bp.target_param}:${bp.payload}`));
          uniquePayloads.unshift(...toInject);
          this.logger.log(
            `fragment: injected ${toInject.length} template-breakout payloads for ${targetUrl}`,
          );
        }

        // ── FUZZ for this URL ───────────────────────────────────────
        const fuzzStartedAt = Date.now();
        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'FUZZ',
          message: `Fuzzing ${targetUrl} with ${uniquePayloads.length} payloads`,
          details: { url: targetUrl, payloadCount: uniquePayloads.length },
          durationMs: 0,
        });
        await this.scanService.updateStatus(
          scanId,
          ScanStatus.FUZZING,
          ScanPhase.FUZZ,
          pct(0.66),
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(0.66),
          message: `[${i + 1}/${totalTargets}] fuzzing ${targetUrl} with ${uniquePayloads.length} payloads${
            authSession ? ' [authenticated]' : ''
          }`,
        });

        let results;
        try {
          const contextEntries = Object.values(contexts) as Array<{
            reflects_in: string;
            allowed_chars: string[];
            context_confidence: number;
          }>;
          const dominantContext =
            contextEntries.length > 0
              ? contextEntries[0].reflects_in
              : undefined;
          const dominantAllowedChars =
            contextEntries.length > 0
              ? contextEntries[0].allowed_chars
              : undefined;

          const fuzzResp = await this.fuzzerClient.test(
            {
              url: targetUrl,
              payloads: uniquePayloads,
              verifyExecution: scan.options.verifyExecution ?? true,
              timeout: scan.options.timeout ?? 60000,
              context: dominantContext,
              waf,
              allowedChars: dominantAllowedChars,
            },
            authSession,
          );
          results = fuzzResp.results;
        } catch (err) {
          const detail = err instanceof Error ? err.message : 'fuzzer error';
          this.logger.warn(
            `fuzzer failed for ${targetUrl}: ${detail}, skipping`,
          );
          await this.scanService.addAuditLog(
            scanId,
            'FUZZ',
            `Fuzzing failed for ${targetUrl}: ${detail}`,
            {
              url: targetUrl,
              error: detail,
            },
            Date.now() - fuzzStartedAt,
          );
          continue;
        }

        totalPayloadsTested += uniquePayloads.length;
        const confirmedVulns = results.filter((r) => r.vuln);
        let urlVulnCount = 0;
        for (const r of confirmedVulns) {
          const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
          if (await this.scanService.addVuln(scanId, vuln)) {
            this.gateway.emitFinding({ scanId, vuln });
            urlVulnCount++;
          }
        }
        totalVulnsFound += confirmedVulns.length;

        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'FUZZ',
          message: `Tested ${uniquePayloads.length} payloads on ${targetUrl}: ${confirmedVulns.length} vulns`,
          details: {
            url: targetUrl,
            payloadsTested: uniquePayloads.length,
            vulnsFound: confirmedVulns.length,
          },
          durationMs: Date.now() - fuzzStartedAt,
        });

        await this.scanService.addAuditLog(
          scanId,
          'FUZZ',
          `Tested ${uniquePayloads.length} payloads on ${targetUrl}, found ${confirmedVulns.length} vulnerabilities`,
          {
            url: targetUrl,
            payloadsTested: uniquePayloads.length,
            vulnsFound: confirmedVulns.length,
            uniqueVulnsAdded: urlVulnCount,
          },
          Date.now() - fuzzStartedAt,
        );

        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(1),
          message: `[${i + 1}/${totalTargets}] ${confirmedVulns.length} vulns on ${targetUrl} (${totalVulnsFound} total)`,
        });

        const urlDurationMs = Date.now() - urlStartedAt;
        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'FUZZ',
          message: `URL ${i + 1}/${totalTargets} done: ${targetUrl} (${confirmedVulns.length} vulns in ${urlDurationMs}ms)`,
          details: {
            url: targetUrl,
            params: targetParams,
            urlIndex: i,
            totalUrls: totalTargets,
            urlDurationMs,
            payloadsTested: uniquePayloads.length,
            payloadGenDurationMs: Date.now() - payloadGenStartedAt,
            vulnsFound: confirmedVulns.length,
            mode: 'full',
          },
          durationMs: urlDurationMs,
        });
      }

      // ── Stored XSS sub-pipeline ─────────────────────────────────────
      const SKIP_FIELDS = new Set([
        'csrf',
        '_csrf',
        'token',
        '_token',
        'captcha',
        '__RequestVerificationToken',
      ]);
      const storedForms = crawledForms.filter(
        (f) => f.sourceUrl && f.fields.length > 0,
      );

      const storedFormsStartedAt = Date.now();
      if (storedForms.length > 0) {
        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'FUZZ',
          message: `Processing ${storedForms.length} form(s) for stored XSS`,
          details: {
            formCount: storedForms.length,
            forms: storedForms.map((f) => ({
              sourceUrl: f.sourceUrl,
              action: f.action,
              fields: f.fields,
            })),
          },
          durationMs: 0,
        });

        this.logger.log(
          `found ${storedForms.length} stored XSS form candidate(s)`,
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: 86,
          message: `testing ${storedForms.length} form(s) for stored XSS${
            authSession ? ' [authenticated]' : ''
          }`,
        });

        for (const form of storedForms) {
          const actionUrl = new URL(form.action, scan.url).href;
          const displayUrl = form.sourceUrl!;
          const testableFields = form.fields.filter(
            (f) => !SKIP_FIELDS.has(f.toLowerCase()),
          );

          if (testableFields.length === 0) continue;

          const defaultFields: Record<string, string> = {};
          for (const field of form.fields) {
            if (SKIP_FIELDS.has(field.toLowerCase())) continue;
            const fl = field.toLowerCase();
            if (fl.includes('email')) defaultFields[field] = 'test@test.com';
            else if (fl.includes('name')) defaultFields[field] = 'testuser';
            else if (
              fl.includes('website') ||
              fl.includes('url') ||
              fl.includes('homepage')
            )
              defaultFields[field] = 'http://test.com';
            else if (fl.includes('postid') || fl.includes('post_id'))
              defaultFields[field] = this.extractPostId(displayUrl) ?? '1';
            else defaultFields[field] = 'test input';
          }

          const storedContexts: Record<
            string,
            {
              reflects_in: string;
              allowed_chars: string[];
              context_confidence: number;
            }
          > = {};
          for (const field of testableFields) {
            storedContexts[field] = {
              reflects_in: 'html_body',
              allowed_chars: ['<', '>', '"', "'", '/', '(', ')', ';', '='],
              context_confidence: 0.7,
            };
          }

          let storedPayloads;
          try {
            const genResp = await this.payloadClient.generate({
              contexts: storedContexts,
              waf,
              maxPayloads: scan.options.maxPayloadsPerParam ?? 20,
            });
            storedPayloads = genResp.payloads;
          } catch (err) {
            const detail =
              err instanceof Error ? err.message : 'payload-gen error';
            this.logger.warn(
              `stored XSS payload-gen failed: ${detail}, skipping`,
            );
            continue;
          }

          if (storedPayloads.length === 0) continue;

          const maxPerParam = scan.options.maxPayloadsPerParam ?? 10;
          const perParam = new Map<string, Set<string>>();
          const uniqueStored: typeof storedPayloads = [];
          for (const p of storedPayloads) {
            const paramKey = String(p.target_param ?? '');
            if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
            const seen = perParam.get(paramKey)!;
            if (seen.has(p.payload)) continue;
            if (seen.size >= maxPerParam) continue;
            seen.add(p.payload);
            uniqueStored.push(p);
          }

          const formStartedAt = Date.now();
          try {
            const fuzzResp = await this.fuzzerClient.test(
              {
                url: actionUrl,
                payloads: uniqueStored,
                verifyExecution: false,
                timeout: scan.options.timeout ?? 60000,
                storedMode: true,
                displayUrl,
                formFields: defaultFields,
                context: 'html_body',
                waf,
              },
              authSession,
            );

            const storedVulns = fuzzResp.results.filter((r) => r.vuln);
            for (const r of storedVulns) {
              const vuln = this.reportService.buildVuln(scanId, displayUrl, r);
              if (await this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
              }
            }
            totalVulnsFound += storedVulns.length;
            totalPayloadsTested += uniqueStored.length;

            this.scannerLog.append(scanId, {
              timestamp: new Date().toISOString(),
              phase: 'FUZZ',
              message: `Form tested: ${displayUrl} (${uniqueStored.length} payloads, ${storedVulns.length} vulns)`,
              details: {
                sourceUrl: displayUrl,
                actionUrl,
                fields: form.fields,
                testedFields: testableFields,
                payloadsTested: uniqueStored.length,
                formDurationMs: Date.now() - formStartedAt,
                vulnsFound: storedVulns.length,
              },
              durationMs: Date.now() - formStartedAt,
            });
          } catch (err) {
            const detail = err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(`stored XSS fuzzer failed: ${detail}, skipping`);
          }
        }

        this.scannerLog.append(scanId, {
          timestamp: new Date().toISOString(),
          phase: 'FUZZ',
          message: `Stored XSS form processing complete: ${storedForms.length} form(s) processed`,
          details: {
            formCount: storedForms.length,
            totalPayloadsUsed: totalPayloadsTested,
          },
          durationMs: Date.now() - storedFormsStartedAt,
        });
      }

      // ── Phase 5: REPORT ─────────────────────────────────────────────
      this.scannerLog.append(scanId, {
        timestamp: new Date().toISOString(),
        phase: 'REPORT',
        message: 'Generating report',
        durationMs: 0,
      });
      await this.scanService.updateStatus(
        scanId,
        ScanStatus.REPORTING,
        ScanPhase.REPORT,
        90,
      );
      const vulns = await this.scanService.getVulns(scanId);
      const completedAt = new Date();
      const scanForReport = { ...scan, completedAt };

      const auditLogs = await this.scanService.getAuditLogs(scanId);

      const totalPayloadsGenerated = auditPayloadsByUrl
        ? Object.values(auditPayloadsByUrl).reduce(
            (sum, entry) => sum + entry.payloads.length,
            0,
          )
        : totalPayloadsTested;

      const reportUrl = await this.reportService.generate(
        scanId,
        scanForReport,
        vulns,
        scan.options.reportFormat ?? ['html', 'json', 'pdf'],
        {
          auditLogs,
          crawledUrls: allCrawledUrls,
          formsFound: crawledForms,
          wafDetected: waf,
          totalPayloadsGenerated,
          payloadsByUrl: auditPayloadsByUrl,
          injectionPoints: auditInjectionPoints,
        },
      );

      await this.scanService.addAuditLog(
        scanId,
        'REPORT',
        `Report generated for ${totalTargets} target(s) with ${vulns.length} vulnerabilities found`,
        {
          totalTargets,
          totalPayloadsGenerated,
          totalVulns: vulns.length,
          durationMs: Date.now() - startedAt,
          reportUrl,
        },
        Date.now() - startedAt,
      );

      await this.scanService.updateStatus(
        scanId,
        ScanStatus.DONE,
        ScanPhase.REPORT,
        100,
      );

      const durationMs = Date.now() - startedAt;
      this.gateway.emitComplete({
        scanId,
        summary: {
          totalParams: totalUniqueParams,
          paramsTested: totalPayloadsTested,
          vulnsFound: vulns.length,
          durationMs,
        },
        reportUrl,
      });

      this.scannerLog.append(scanId, {
        timestamp: new Date().toISOString(),
        phase: 'REPORT',
        message: `Scan complete: ${totalTargets} target(s), ${totalPayloadsTested} payloads tested, ${vulns.length} vulns found in ${((Date.now() - startedAt) / 1000).toFixed(1)}s`,
        details: {
          totalTargets,
          totalPayloadsTested,
          totalVulns: vulns.length,
          durationMs,
        },
      });
      this.scannerLog.flush(scanId, {
        targetUrl: scan.url,
        startedAt: new Date(startedAt),
        status: 'COMPLETED',
      });

      this.logger.log(
        `scan complete scanId=${scanId} targets=${totalTargets} vulns=${vulns.length} ms=${durationMs}${
          authSession ? ' [authenticated]' : ''
        }`,
      );
    } catch (err: unknown) {
      const msg: string = err instanceof Error ? err.message : 'unknown error';
      this.logger.error(`scan failed scanId=${scanId} error=${msg}`);
      await this.scanService.markFailed(scanId, msg);
      await this.scanService.addAuditLog(
        scanId,
        'FAIL',
        `Scan failed: ${msg}`,
        { error: msg },
        Date.now() - startedAt,
      );
      this.scannerLog.flush(scanId, {
        targetUrl: scanId,
        startedAt: new Date(startedAt),
        status: 'FAILED',
      });
      this.gateway.emitError(scanId, msg);
    }
  }
}

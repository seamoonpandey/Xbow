import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { ScanService } from '../scan/scan.service';
import { ScanGateway } from '../scan/scan.gateway';
import { CrawlerService } from '../crawler/crawler.service';
import { ContextClientService } from '../modules-bridge/context-client.service';
import { PayloadClientService } from '../modules-bridge/payload-client.service';
import { FuzzerClientService } from '../modules-bridge/fuzzer-client.service';
import { ReportService } from '../report/report.service';
import { ScanStatus, ScanPhase } from '../common/interfaces/scan.interface';
import { SCAN_QUEUE } from './scan.producer';

@Processor(SCAN_QUEUE)
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
  ) {
    super();
  }

  async process(job: Job<{ scanId: string }>): Promise<void> {
    const { scanId } = job.data;
    const scan = this.scanService.findOne(scanId);
    const startedAt = Date.now();

    try {
      // ── Phase 1: CRAWL ──────────────────────────────────────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.CRAWLING,
        ScanPhase.CRAWL,
        5,
      );
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 5,
        message: 'crawling target, discovering params',
      });

      const crawlResult = await this.crawlerService.crawl(
        scan.url,
        scan.options.depth ?? 3,
        scan.options.maxParams ?? 100,
      );

      const waf = crawlResult.waf.name ?? 'none';

      // ── Build per-URL param map from discovered URLs ────────────────
      // The crawler returns individual URLs it visited; we extract query
      // params from each so that context/fuzz target the actual page
      // that handles each parameter, not just the root URL.
      const urlParamsMap = new Map<string, string[]>();
      for (const crawledUrl of crawlResult.urls) {
        try {
          const u = new URL(crawledUrl);
          const params = [...new Set(u.searchParams.keys())];
          if (params.length > 0) {
            urlParamsMap.set(crawledUrl, params);
          }
        } catch {
          // skip invalid URLs
        }
      }

      // Also include form action URLs with their fields
      for (const form of crawlResult.forms) {
        if (form.action && form.fields.length > 0) {
          const existing = urlParamsMap.get(form.action) ?? [];
          const merged = [...new Set([...existing, ...form.fields])];
          urlParamsMap.set(form.action, merged);
        }
      }

      // If the original scan URL has params, ensure it's included
      try {
        const rootUrl = new URL(scan.url);
        const rootParams = [...new Set(rootUrl.searchParams.keys())];
        if (rootParams.length > 0 && !urlParamsMap.has(scan.url)) {
          urlParamsMap.set(scan.url, rootParams);
        }
      } catch {
        // skip
      }

      const targetEntries = Array.from(urlParamsMap.entries());
      const totalUniqueParams = new Set(
        targetEntries.flatMap(([, params]) => params),
      ).size;

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 20,
        message: `found ${totalUniqueParams} params across ${crawlResult.urls.length} urls, ${targetEntries.length} targets${crawlResult.waf.detected ? `, waf: ${waf}` : ''}`,
      });

      if (targetEntries.length === 0) {
        this.logger.warn(
          `no parameterized URLs found for scanId=${scanId}, nothing to test`,
        );
        this.scanService.updateStatus(
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

      // ── Per-URL pipeline: CONTEXT → PAYLOAD-GEN → FUZZ ─────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.ANALYZING,
        ScanPhase.CONTEXT,
        25,
      );

      let totalPayloadsTested = 0;
      let totalVulnsFound = 0;
      const totalTargets = targetEntries.length;

      for (let i = 0; i < totalTargets; i++) {
        const [targetUrl, targetParams] = targetEntries[i];
        const pct = (n: number) =>
          Math.round(25 + ((i + n) / totalTargets) * 60);

        this.logger.log(
          `[${i + 1}/${totalTargets}] processing ${targetUrl} (${targetParams.length} params)`,
        );

        // ── CONTEXT for this URL ────────────────────────────────────
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.CONTEXT,
          progress: pct(0),
          message: `[${i + 1}/${totalTargets}] analyzing ${targetUrl}`,
        });

        let contexts;
        try {
          contexts = await this.contextClient.analyze({
            url: targetUrl,
            params: targetParams,
            waf,
          });
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'context module error';
          this.logger.warn(
            `context failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        // skip if no reflections found for this URL
        const reflectedParams = Object.entries(contexts).filter(
          ([, ctx]) =>
            (ctx as { reflects_in: string }).reflects_in !== 'none',
        );
        if (reflectedParams.length === 0) {
          this.logger.debug(`no reflections on ${targetUrl}, skipping`);
          continue;
        }

        this.logger.log(
          `${reflectedParams.length} reflecting params on ${targetUrl}`,
        );

        // ── PAYLOAD-GEN for this URL ────────────────────────────────
        this.scanService.updateStatus(
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
            maxPayloads: scan.options.maxPayloadsPerParam ?? 50,
          });
          payloads = genResp.payloads;
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'payload-gen error';
          this.logger.warn(
            `payload-gen failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        if (payloads.length === 0) {
          this.logger.debug(`no payloads generated for ${targetUrl}`);
          continue;
        }

        // ── FUZZ for this URL ───────────────────────────────────────
        this.scanService.updateStatus(
          scanId,
          ScanStatus.FUZZING,
          ScanPhase.FUZZ,
          pct(0.66),
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(0.66),
          message: `[${i + 1}/${totalTargets}] fuzzing ${targetUrl} with ${payloads.length} payloads`,
        });

        let results;
        try {
          const fuzzResp = await this.fuzzerClient.test({
            url: targetUrl,
            payloads,
            verifyExecution: scan.options.verifyExecution ?? true,
            timeout: scan.options.timeout ?? 60000,
          });
          results = fuzzResp.results;
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'fuzzer error';
          this.logger.warn(
            `fuzzer failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        totalPayloadsTested += payloads.length;
        const confirmedVulns = results.filter((r) => r.vuln);
        for (const r of confirmedVulns) {
          const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
          this.scanService.addVuln(scanId, vuln);
          this.gateway.emitFinding({ scanId, vuln });
        }
        totalVulnsFound += confirmedVulns.length;

        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(1),
          message: `[${i + 1}/${totalTargets}] ${confirmedVulns.length} vulns on ${targetUrl} (${totalVulnsFound} total)`,
        });
      }

      // ── Phase 5: REPORT ─────────────────────────────────────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.REPORTING,
        ScanPhase.REPORT,
        90,
      );
      const vulns = this.scanService.getVulns(scanId);
      const reportUrl = await this.reportService.generate(
        scanId,
        scan,
        vulns,
        scan.options.reportFormat ?? ['html', 'json', 'pdf'],
      );

      this.scanService.updateStatus(
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

      this.logger.log(
        `scan complete scanId=${scanId} targets=${totalTargets} vulns=${vulns.length} ms=${durationMs}`,
      );
    } catch (err: unknown) {
      const msg: string = err instanceof Error ? err.message : 'unknown error';
      this.logger.error(`scan failed scanId=${scanId} error=${msg}`);
      this.scanService.markFailed(scanId, msg);
      this.gateway.emitError(scanId, msg);
      // don't re-throw — scan is already marked FAILED,
      // retrying would hit "already running" guard
    }
  }
}

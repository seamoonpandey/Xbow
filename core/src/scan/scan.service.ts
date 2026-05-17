import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomUUID as uuidv4 } from 'crypto';
import { CreateScanDto } from './dto/create-scan.dto';
import {
  ScanRecord,
  ScanStatus,
  ScanPhase,
} from '../common/interfaces/scan.interface';
import { Vuln } from '../common/interfaces/vuln.interface';
import {
  ScanNotFoundException,
  ScanAlreadyRunningException,
  ScanCancelException,
} from '../common/exceptions/scan.exceptions';
import { normalizeUrl } from '../common/utils/url.utils';
import { ScanEntity } from './entities/scan.entity';
import { VulnEntity } from './entities/vuln.entity';
import { ScanAuditEntity } from './entities/scan-audit.entity';

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  /**
   * In-memory dedup sets survive only for the lifetime of the process.
   * This is fine — dedup only matters during a single scan run; if the
   * process restarts mid-scan, BullMQ will re-queue the job anyway.
   */
  private readonly vulnKeys = new Map<
    string,
    Map<string, { id: string; score: number }>
  >();

  constructor(
    @InjectRepository(ScanEntity)
    private readonly scanRepo: Repository<ScanEntity>,
    @InjectRepository(VulnEntity)
    private readonly vulnRepo: Repository<VulnEntity>,
    @InjectRepository(ScanAuditEntity)
    private readonly auditRepo: Repository<ScanAuditEntity>,
  ) {}

  async create(dto: CreateScanDto, userId?: string): Promise<ScanRecord> {
    const id = uuidv4();
    const now = new Date();
    const entity = this.scanRepo.create({
      id,
      url: normalizeUrl(dto.url),
      status: ScanStatus.PENDING,
      progress: 0,
      userId,
      options: {
        depth: dto.options?.depth ?? 3,
        maxParams: dto.options?.maxParams ?? 100,
        verifyExecution: dto.options?.verifyExecution ?? true,
        wafBypass: dto.options?.wafBypass ?? true,
        maxPayloadsPerParam: dto.options?.maxPayloadsPerParam ?? 50,
        timeout: dto.options?.timeout ?? 60000,
        reportFormat: dto.options?.reportFormat ?? ['html', 'json'],
        auth: dto.options?.auth ?? undefined,
      },
      createdAt: now,
      updatedAt: now,
    });
    const saved = await this.scanRepo.save(entity);
    this.vulnKeys.set(id, new Map());
    this.logger.log(`scan created id=${id} url=${saved.url} userId=${userId ?? 'anonymous'}`);
    return this.toRecord(saved);
  }

  async findOne(id: string, userId?: string): Promise<ScanRecord> {
    if (userId) {
      const scan = await this.scanRepo.findOneBy({ id, userId } as any);
      if (scan) return this.toRecord(scan);
    }
    const scan = await this.scanRepo.findOneBy({ id } as any);
    if (!scan) throw new ScanNotFoundException(id);
    return this.toRecord(scan);
  }

  async findAll(userId?: string): Promise<ScanRecord[]> {
    const where: Record<string, unknown> = {};
    if (userId) where.userId = userId;
    const scans = await this.scanRepo.find({
      where: where as any,
      order: { createdAt: 'DESC' },
    });
    return scans.map((s) => this.toRecord(s));
  }

  async getVulns(id: string): Promise<Vuln[]> {
    await this.findOne(id);
    const entities = await this.vulnRepo.find({
      where: { scanId: id },
      order: { discoveredAt: 'ASC' },
    });
    return entities.map((e) => this.toVuln(e));
  }

  async cancel(id: string): Promise<ScanRecord> {
    const scan = await this.findOne(id);
    const cancellable: ScanStatus[] = [
      ScanStatus.PENDING,
      ScanStatus.CRAWLING,
      ScanStatus.ANALYZING,
      ScanStatus.GENERATING,
      ScanStatus.FUZZING,
    ];
    if (!cancellable.includes(scan.status)) {
      throw new ScanCancelException(id);
    }
    return this.updateStatus(id, ScanStatus.CANCELLED);
  }

  async updateStatus(
    id: string,
    status: ScanStatus,
    phase?: ScanPhase,
    progress?: number,
  ): Promise<ScanRecord> {
    const scan = await this.findOne(id);
    // Allow re-entering CRAWLING if already crawling (e.g. after auth → crawl phase transition)
    if (status === ScanStatus.CRAWLING && !this.isIdle(scan) && scan.status !== ScanStatus.CRAWLING) {
      throw new ScanAlreadyRunningException(id);
    }

    const updates: Partial<ScanEntity> = {
      status,
      updatedAt: new Date(),
    };
    if (phase !== undefined) updates.phase = phase;
    if (progress !== undefined) updates.progress = progress;
    if (
      status === ScanStatus.DONE ||
      status === ScanStatus.FAILED ||
      status === ScanStatus.CANCELLED
    ) {
      updates.completedAt = new Date();
    }

    await this.scanRepo.update(id, updates);
    return this.findOne(id);
  }

  async addVuln(scanId: string, vuln: Vuln): Promise<boolean> {
    await this.findOne(scanId);
    const key = this.buildVulnKey(vuln);
    const seen =
      this.vulnKeys.get(scanId) ??
      new Map<string, { id: string; score: number }>();

    // PostgreSQL rejects null bytes (\x00) in text columns.
    // XSS payloads legitimately contain them (e.g. <\x00a …>) so strip
    // before persisting rather than letting the INSERT fail.
    const stripNullBytes = (s: string | undefined): string | undefined =>
      s == null ? s : s.split('\u0000').join('');

    const sanitizeUnknown = (value: unknown): unknown => {
      if (typeof value === 'string') {
        return value.split('\u0000').join('').split('\\u0000').join('');
      }
      if (Array.isArray(value)) {
        return value.map((item) => sanitizeUnknown(item));
      }
      if (value && typeof value === 'object') {
        const input = value as Record<string, unknown>;
        const output: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(input)) {
          output[k] = sanitizeUnknown(v);
        }
        return output;
      }
      return value;
    };

    const sanitizeEvidence = (value: Vuln['evidence']): Vuln['evidence'] =>
      sanitizeUnknown(value) as Vuln['evidence'];

    const sanitizedEvidence =
      vuln.evidence != null ? sanitizeEvidence(vuln.evidence) : vuln.evidence;

    const entity = this.vulnRepo.create({
      id: vuln.id ?? uuidv4(),
      scanId,
      url: stripNullBytes(vuln.url) ?? vuln.url,
      param: stripNullBytes(vuln.param),
      payload: stripNullBytes(vuln.payload) ?? vuln.payload,
      type: vuln.type,
      severity: vuln.severity,
      reflected: vuln.reflected,
      executed: vuln.executed,
      evidence: sanitizedEvidence,
      discoveredAt: vuln.discoveredAt ?? new Date(),
    });

    const score = this.scoreVuln(vuln);
    const existing = seen.get(key);

    if (existing) {
      // Keep the best representative finding for this dedup key.
      if (score <= existing.score) return false;

      await this.vulnRepo.update(
        { id: existing.id, scanId },
        {
          url: entity.url,
          param: entity.param,
          payload: entity.payload,
          type: entity.type,
          severity: entity.severity,
          reflected: entity.reflected,
          executed: entity.executed,
          evidence: entity.evidence,
          discoveredAt: entity.discoveredAt,
        },
      );

      seen.set(key, { id: existing.id, score });
      this.vulnKeys.set(scanId, seen);
      return false;
    }

    await this.vulnRepo.save(entity);
    seen.set(key, { id: entity.id, score });
    this.vulnKeys.set(scanId, seen);
    return true;
  }

  async markFailed(id: string, error: string): Promise<ScanRecord> {
    await this.scanRepo.update(id, {
      status: ScanStatus.FAILED,
      error,
      updatedAt: new Date(),
      completedAt: new Date(),
    });
    return this.findOne(id);
  }

  // ── audit log ────────────────────────────────────────────────

  async addAuditLog(
    scanId: string,
    phase: string,
    message: string,
    data?: Record<string, unknown>,
    durationMs?: number,
  ): Promise<void> {
    try {
      const entity = this.auditRepo.create({
        id: uuidv4(),
        scanId,
        phase,
        step: 0,
        message,
        data: data ?? undefined,
        durationMs,
      });
      await this.auditRepo.save(entity);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      this.logger.warn(`failed to write audit log for scanId=${scanId}: ${detail}`);
    }
  }

  async getAuditLogs(scanId: string): Promise<ScanAuditEntity[]> {
    return this.auditRepo.find({
      where: { scanId },
      order: { createdAt: 'ASC' },
    });
  }

  // ── delete / clear operations ────────────────────────────────

  async deleteScan(id: string): Promise<void> {
    const scan = await this.scanRepo.findOneBy({ id });
    if (!scan) throw new ScanNotFoundException(id);
    await this.scanRepo.remove(scan);
    this.vulnKeys.delete(id);
    this.logger.log(`scan deleted id=${id}`);
  }

  async deleteAllScans(): Promise<number> {
    const count = await this.scanRepo.count();
    await this.vulnRepo.clear();
    await this.scanRepo.clear();
    this.vulnKeys.clear();
    this.logger.warn(`all scans deleted (${count} scans removed)`);
    return count;
  }

  // ── private helpers ──────────────────────────────────────────

  private toRecord(e: ScanEntity): ScanRecord {
    return {
      id: e.id,
      url: e.url,
      status: e.status,
      phase: e.phase,
      progress: e.progress,
      options: e.options,
      userId: e.userId ?? undefined,
      createdAt: e.createdAt,
      updatedAt: e.updatedAt,
      completedAt: e.completedAt ?? undefined,
      error: e.error ?? undefined,
    };
  }

  private toVuln(e: VulnEntity): Vuln {
    return {
      id: e.id,
      scanId: e.scanId,
      url: e.url,
      param: e.param,
      payload: e.payload,
      type: e.type,
      severity: e.severity,
      reflected: e.reflected,
      executed: e.executed,
      evidence: e.evidence,
      discoveredAt: e.discoveredAt,
    };
  }

  private buildVulnKey(v: Vuln): string {
    const page = this.normalizeUrlForDedup(String(v.url ?? '').trim());
    const source = String(v.evidence?.source ?? 'URLSearchParams').trim();
    const sink = String(
      v.evidence?.sink ?? v.evidence?.reflectionPosition ?? 'attribute',
    ).trim();
    return `${page}::${source}::${sink}`;
  }

  private normalizeUrlForDedup(rawUrl: string): string {
    try {
      const u = new URL(rawUrl);
      const keys = [...new Set([...u.searchParams.keys()])].sort();
      const qs =
        keys.length > 0
          ? `?${keys.map((k) => `${encodeURIComponent(k)}=`).join('&')}`
          : '';
      return `${u.origin}${u.pathname}${qs}`;
    } catch {
      return rawUrl;
    }
  }

  private isIdle(scan: ScanRecord): boolean {
    return scan.status === ScanStatus.PENDING;
  }

  private scoreVuln(v: Vuln): number {
    const severityRank: Record<string, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };
    const sev = severityRank[String(v.severity ?? '').toUpperCase()] ?? 1;
    const evidence = (v.evidence ?? {}) as unknown as Record<string, unknown>;
    const alertTriggered = Boolean(evidence.browserAlertTriggered);

    let score = sev;
    if (v.reflected) score += 5;
    if (v.executed) score += 50;
    if (alertTriggered) score += 20;

    const p = String(v.payload ?? '').toLowerCase();
    if (p.includes('document.cookie') || p.includes('localstorage')) score += 5;
    if (p.includes('onerror=') || p.includes('onload=')) score += 2;

    return score;
  }
}

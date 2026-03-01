import { ScanService } from './scan.service';
import { ScanStatus, ScanPhase } from '../common/interfaces/scan.interface';
import {
  ScanNotFoundException,
  ScanAlreadyRunningException,
  ScanCancelException,
} from '../common/exceptions/scan.exceptions';

describe('ScanService', () => {
  let service: ScanService;

  beforeEach(() => {
    service = new ScanService();
  });

  describe('create', () => {
    it('creates a scan with default options', () => {
      const scan = service.create({ url: 'https://example.com' });
      expect(scan.id).toBeDefined();
      expect(scan.url).toBe('https://example.com');
      expect(scan.status).toBe(ScanStatus.PENDING);
      expect(scan.progress).toBe(0);
      expect(scan.options.depth).toBe(3);
      expect(scan.options.maxPayloadsPerParam).toBe(50);
      expect(scan.options.verifyExecution).toBe(true);
      expect(scan.options.wafBypass).toBe(true);
      expect(scan.createdAt).toBeInstanceOf(Date);
    });

    it('normalizes url by stripping trailing slash', () => {
      const scan = service.create({ url: 'https://example.com/' });
      expect(scan.url).toBe('https://example.com');
    });

    it('throws on invalid url', () => {
      expect(() => service.create({ url: 'not-a-url' })).toThrow();
    });

    it('respects custom options', () => {
      const scan = service.create({
        url: 'https://example.com',
        options: { depth: 5, maxPayloadsPerParam: 100 },
      });
      expect(scan.options.depth).toBe(5);
      expect(scan.options.maxPayloadsPerParam).toBe(100);
    });

    it('initializes empty vuln list', () => {
      const scan = service.create({ url: 'https://example.com' });
      expect(service.getVulns(scan.id)).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('returns existing scan', () => {
      const created = service.create({ url: 'https://example.com' });
      const found = service.findOne(created.id);
      expect(found.id).toBe(created.id);
    });

    it('throws ScanNotFoundException for unknown id', () => {
      expect(() => service.findOne('nonexistent')).toThrow(
        ScanNotFoundException,
      );
    });
  });

  describe('findAll', () => {
    it('returns empty array when no scans exist', () => {
      expect(service.findAll()).toEqual([]);
    });

    it('returns scans sorted by createdAt descending', () => {
      const s1 = service.create({ url: 'https://a.com' });
      // nudge s1 creation time back so sort order is deterministic
      s1.createdAt = new Date(Date.now() - 1000);
      const s2 = service.create({ url: 'https://b.com' });
      const all = service.findAll();
      expect(all.length).toBe(2);
      // s2 was created after s1
      expect(all[0].id).toBe(s2.id);
      expect(all[1].id).toBe(s1.id);
    });
  });

  describe('getVulns', () => {
    it('throws for unknown scan id', () => {
      expect(() => service.getVulns('nonexistent')).toThrow(
        ScanNotFoundException,
      );
    });

    it('returns added vulns', () => {
      const scan = service.create({ url: 'https://example.com' });
      const vuln = {
        id: 'v1',
        scanId: scan.id,
        url: 'https://example.com',
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: 'REFLECTED_XSS' as any,
        severity: 'HIGH' as any,
        reflected: true,
        executed: true,
        evidence: {
          responseCode: 200,
          reflectionPosition: 'body',
          browserAlertTriggered: true,
        },
        discoveredAt: new Date(),
      };
      service.addVuln(scan.id, vuln);
      expect(service.getVulns(scan.id)).toHaveLength(1);
      expect(service.getVulns(scan.id)[0].param).toBe('q');
    });
  });

  describe('cancel', () => {
    it('cancels a pending scan', () => {
      const scan = service.create({ url: 'https://example.com' });
      const cancelled = service.cancel(scan.id);
      expect(cancelled.status).toBe(ScanStatus.CANCELLED);
      expect(cancelled.completedAt).toBeInstanceOf(Date);
    });

    it('cancels a crawling scan', () => {
      const scan = service.create({ url: 'https://example.com' });
      service.updateStatus(scan.id, ScanStatus.CRAWLING, ScanPhase.CRAWL, 10);
      const cancelled = service.cancel(scan.id);
      expect(cancelled.status).toBe(ScanStatus.CANCELLED);
    });

    it('throws ScanCancelException for a completed scan', () => {
      const scan = service.create({ url: 'https://example.com' });
      service.updateStatus(scan.id, ScanStatus.DONE);
      expect(() => service.cancel(scan.id)).toThrow(ScanCancelException);
    });

    it('throws ScanCancelException for a failed scan', () => {
      const scan = service.create({ url: 'https://example.com' });
      service.markFailed(scan.id, 'some error');
      expect(() => service.cancel(scan.id)).toThrow(ScanCancelException);
    });
  });

  describe('updateStatus', () => {
    it('updates status, phase, and progress', () => {
      const scan = service.create({ url: 'https://example.com' });
      const updated = service.updateStatus(
        scan.id,
        ScanStatus.CRAWLING,
        ScanPhase.CRAWL,
        25,
      );
      expect(updated.status).toBe(ScanStatus.CRAWLING);
      expect(updated.phase).toBe(ScanPhase.CRAWL);
      expect(updated.progress).toBe(25);
    });

    it('throws ScanAlreadyRunningException when starting already running scan', () => {
      const scan = service.create({ url: 'https://example.com' });
      service.updateStatus(scan.id, ScanStatus.CRAWLING, ScanPhase.CRAWL, 10);
      expect(() =>
        service.updateStatus(scan.id, ScanStatus.CRAWLING),
      ).toThrow(ScanAlreadyRunningException);
    });

    it('sets completedAt for terminal statuses', () => {
      const scan = service.create({ url: 'https://example.com' });
      expect(scan.completedAt).toBeUndefined();
      service.updateStatus(scan.id, ScanStatus.DONE);
      expect(scan.completedAt).toBeInstanceOf(Date);
    });
  });

  describe('markFailed', () => {
    it('sets status to FAILED with error message', () => {
      const scan = service.create({ url: 'https://example.com' });
      const failed = service.markFailed(scan.id, 'timeout');
      expect(failed.status).toBe(ScanStatus.FAILED);
      expect(failed.error).toBe('timeout');
      expect(failed.completedAt).toBeInstanceOf(Date);
    });
  });
});

import { Test } from '@nestjs/testing';
import { ScanController } from './scan.controller';
import { ScanService } from './scan.service';
import { ScanQueueProducer } from '../queue/scan.producer';
import { ApiKeyGuard } from '../auth/api-key.guard';
import { ScanStatus } from '../common/interfaces/scan.interface';

describe('ScanController', () => {
  let controller: ScanController;
  let scanService: ScanService;
  let queueProducer: ScanQueueProducer;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      controllers: [ScanController],
      providers: [
        ScanService,
        {
          provide: ScanQueueProducer,
          useValue: { enqueue: jest.fn().mockResolvedValue(undefined) },
        },
      ],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(ScanController);
    scanService = module.get(ScanService);
    queueProducer = module.get(ScanQueueProducer);
  });

  describe('createScan', () => {
    it('creates a scan and enqueues it', async () => {
      const result = await controller.createScan({
        url: 'https://example.com',
      });
      expect(result).toBeDefined();
      expect(result.url).toBe('https://example.com');
      expect(queueProducer.enqueue).toHaveBeenCalledWith(result.id);
    });
  });

  describe('getScan', () => {
    it('returns scan with vulns', () => {
      const scan = scanService.create({ url: 'https://example.com' });
      const result = controller.getScan(scan.id);
      expect(result.id).toBe(scan.id);
      expect(result.vulns).toEqual([]);
    });
  });

  describe('cancelScan', () => {
    it('cancels a pending scan', () => {
      const scan = scanService.create({ url: 'https://example.com' });
      expect(() => controller.cancelScan(scan.id)).not.toThrow();
      expect(scanService.findOne(scan.id).status).toBe(ScanStatus.CANCELLED);
    });
  });

  describe('listScans', () => {
    it('returns paginated list', () => {
      for (let i = 0; i < 5; i++) {
        scanService.create({ url: `https://${i}.com` });
      }
      const page1 = controller.listScans(1, 2);
      expect(page1).toHaveLength(2);

      const page3 = controller.listScans(3, 2);
      expect(page3).toHaveLength(1);
    });

    it('returns empty for out-of-range page', () => {
      scanService.create({ url: 'https://example.com' });
      const result = controller.listScans(100, 20);
      expect(result).toHaveLength(0);
    });
  });

  describe('getReport', () => {
    it('returns report url for existing scan', () => {
      const scan = scanService.create({ url: 'https://example.com' });
      const result = controller.getReport(scan.id);
      expect(result.reportUrl).toContain(scan.id);
    });
  });

  describe('health', () => {
    it('returns ok status', () => {
      const result = controller.health();
      expect(result.status).toBe('ok');
      expect(result.timestamp).toBeDefined();
    });
  });
});

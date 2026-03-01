import { ScanQueueProducer, SCAN_QUEUE } from './scan.producer';

describe('ScanQueueProducer', () => {
  let producer: ScanQueueProducer;
  let mockQueue: { add: jest.Mock };

  beforeEach(() => {
    mockQueue = { add: jest.fn().mockResolvedValue({}) };
    producer = new ScanQueueProducer(mockQueue as any);
  });

  describe('enqueue', () => {
    it('adds a job to the queue with correct data', async () => {
      await producer.enqueue('scan-123');
      expect(mockQueue.add).toHaveBeenCalledWith(
        'run-scan',
        { scanId: 'scan-123' },
        expect.objectContaining({
          attempts: 2,
          backoff: { type: 'exponential', delay: 2000 },
        }),
      );
    });

    it('sets removeOnComplete and removeOnFail', async () => {
      await producer.enqueue('scan-456');
      expect(mockQueue.add).toHaveBeenCalledWith(
        'run-scan',
        expect.anything(),
        expect.objectContaining({
          removeOnComplete: 100,
          removeOnFail: 50,
        }),
      );
    });
  });

  it('exports SCAN_QUEUE constant', () => {
    expect(SCAN_QUEUE).toBe('scan');
  });
});

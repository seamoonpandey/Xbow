/**
 * integration test — websocket events
 * boots a real nestjs app with socket.io gateway, connects a
 * socket.io-client, and verifies real-time scan events.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { io, Socket } from 'socket.io-client';
import { ScanGateway, ProgressPayload, FindingPayload, CompletePayload } from '../src/scan/scan.gateway';
import { ScanPhase } from '../src/common/interfaces/scan.interface';

describe('websocket events (integration)', () => {
  let app: INestApplication;
  let gateway: ScanGateway;
  let client: Socket;
  let port: number;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      providers: [ScanGateway],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    // listen on random port
    const server = app.getHttpServer();
    await new Promise<void>((resolve) => server.listen(0, resolve));
    port = server.address().port;

    gateway = moduleFixture.get(ScanGateway);
  });

  afterAll(async () => {
    if (client?.connected) client.disconnect();
    await app.close();
  });

  beforeEach(async () => {
    client = io(`http://localhost:${port}`, {
      transports: ['websocket'],
      forceNew: true,
    });

    await new Promise<void>((resolve, reject) => {
      client.on('connect', resolve);
      client.on('connect_error', reject);
      setTimeout(() => reject(new Error('ws connect timeout')), 5000);
    });
  });

  afterEach(() => {
    if (client?.connected) client.disconnect();
  });

  it('client connects successfully', () => {
    expect(client.connected).toBe(true);
  });

  it('receives scan:progress events', async () => {
    const received = new Promise<ProgressPayload>((resolve) => {
      client.on('scan:progress', (data: ProgressPayload) => resolve(data));
    });

    const payload: ProgressPayload = {
      scanId: 'scan-123',
      phase: ScanPhase.CRAWL,
      progress: 15,
      message: 'discovered 5 params',
    };

    // small delay to ensure listener is registered
    await new Promise((r) => setTimeout(r, 50));
    gateway.emitProgress(payload);

    const data = await received;
    expect(data.scanId).toBe('scan-123');
    expect(data.phase).toBe(ScanPhase.CRAWL);
    expect(data.progress).toBe(15);
    expect(data.message).toBe('discovered 5 params');
  });

  it('receives scan:finding events', async () => {
    const received = new Promise<FindingPayload>((resolve) => {
      client.on('scan:finding', (data: FindingPayload) => resolve(data));
    });

    const payload: FindingPayload = {
      scanId: 'scan-456',
      vuln: {
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: 'reflected_xss' as any,
        severity: 'HIGH' as any,
        reflected: true,
        executed: true,
      },
    };

    await new Promise((r) => setTimeout(r, 50));
    gateway.emitFinding(payload);

    const data = await received;
    expect(data.scanId).toBe('scan-456');
    expect(data.vuln.param).toBe('q');
    expect(data.vuln.reflected).toBe(true);
  });

  it('receives scan:complete events', async () => {
    const received = new Promise<CompletePayload>((resolve) => {
      client.on('scan:complete', (data: CompletePayload) => resolve(data));
    });

    const payload: CompletePayload = {
      scanId: 'scan-789',
      summary: {
        totalParams: 10,
        paramsTested: 10,
        vulnsFound: 3,
        durationMs: 45000,
      },
      reportUrl: '/reports/scan-789.html',
    };

    await new Promise((r) => setTimeout(r, 50));
    gateway.emitComplete(payload);

    const data = await received;
    expect(data.scanId).toBe('scan-789');
    expect(data.summary.vulnsFound).toBe(3);
    expect(data.reportUrl).toContain('scan-789');
  });

  it('receives scan:error events', async () => {
    const received = new Promise<{ scanId: string; message: string }>((resolve) => {
      client.on('scan:error', (data: { scanId: string; message: string }) => resolve(data));
    });

    await new Promise((r) => setTimeout(r, 50));
    gateway.emitError('scan-fail', 'context module timeout');

    const data = await received;
    expect(data.scanId).toBe('scan-fail');
    expect(data.message).toContain('timeout');
  });

  it('multiple clients receive the same event', async () => {
    const client2 = io(`http://localhost:${port}`, {
      transports: ['websocket'],
      forceNew: true,
    });

    await new Promise<void>((resolve, reject) => {
      client2.on('connect', resolve);
      client2.on('connect_error', reject);
      setTimeout(() => reject(new Error('ws connect timeout')), 5000);
    });

    const promise1 = new Promise<ProgressPayload>((resolve) => {
      client.on('scan:progress', resolve);
    });
    const promise2 = new Promise<ProgressPayload>((resolve) => {
      client2.on('scan:progress', resolve);
    });

    await new Promise((r) => setTimeout(r, 50));
    gateway.emitProgress({
      scanId: 'broadcast-test',
      phase: ScanPhase.FUZZ,
      progress: 70,
      message: 'fuzzing',
    });

    const [data1, data2] = await Promise.all([promise1, promise2]);
    expect(data1.scanId).toBe('broadcast-test');
    expect(data2.scanId).toBe('broadcast-test');

    client2.disconnect();
  });
});

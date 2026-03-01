export enum ScanStatus {
  PENDING = 'PENDING',
  CRAWLING = 'CRAWLING',
  ANALYZING = 'ANALYZING',
  GENERATING = 'GENERATING',
  FUZZING = 'FUZZING',
  REPORTING = 'REPORTING',
  DONE = 'DONE',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum ScanPhase {
  CRAWL = 'CRAWL',
  CONTEXT = 'CONTEXT',
  PAYLOAD_GEN = 'PAYLOAD_GEN',
  FUZZ = 'FUZZ',
  REPORT = 'REPORT',
}

export interface ScanOptions {
  depth?: number;
  maxParams?: number;
  verifyExecution?: boolean;
  wafBypass?: boolean;
  maxPayloadsPerParam?: number;
  timeout?: number;
  reportFormat?: ('html' | 'json' | 'pdf')[];
}

export interface ScanRecord {
  id: string;
  url: string;
  status: ScanStatus;
  phase?: ScanPhase;
  progress: number;
  options: ScanOptions;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
  error?: string;
}

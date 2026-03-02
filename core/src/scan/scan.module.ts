import { Module, forwardRef } from '@nestjs/common';
import { ScanController } from './scan.controller';
import { ScanService } from './scan.service';
import { ScanGateway } from './scan.gateway';
import { QueueModule } from '../queue/queue.module';
import { AuthModule } from '../auth/auth.module';
import { CrawlerModule } from '../crawler/crawler.module';

@Module({
  imports: [forwardRef(() => QueueModule), AuthModule, CrawlerModule],
  controllers: [ScanController],
  providers: [ScanService, ScanGateway],
  exports: [ScanService, ScanGateway],
})
export class ScanModule {}

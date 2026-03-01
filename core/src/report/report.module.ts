import { Module, forwardRef } from '@nestjs/common';
import { ReportService } from './report.service';
import { ReportController } from './report.controller';
import { ScanModule } from '../scan/scan.module';

@Module({
  imports: [forwardRef(() => ScanModule)],
  controllers: [ReportController],
  providers: [ReportService],
  exports: [ReportService],
})
export class ReportModule {}

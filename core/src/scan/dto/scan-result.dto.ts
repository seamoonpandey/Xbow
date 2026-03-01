import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ScanStatus, ScanPhase } from '../../common/interfaces/scan.interface';
import { Vuln } from '../../common/interfaces/vuln.interface';

export class ScanResultDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  url!: string;

  @ApiProperty({ enum: ScanStatus })
  status!: ScanStatus;

  @ApiPropertyOptional({ enum: ScanPhase })
  phase?: ScanPhase;

  @ApiProperty()
  progress!: number;

  @ApiPropertyOptional()
  vulns?: Vuln[];

  @ApiPropertyOptional()
  summary?: ScanSummaryDto;

  @ApiProperty()
  createdAt!: Date;

  @ApiPropertyOptional()
  completedAt?: Date;

  @ApiPropertyOptional()
  error?: string;
}

export class ScanSummaryDto {
  @ApiProperty()
  totalParams!: number;

  @ApiProperty()
  paramsTested!: number;

  @ApiProperty()
  vulnsFound!: number;

  @ApiProperty()
  durationMs!: number;

  @ApiPropertyOptional()
  reportUrl?: string;
}

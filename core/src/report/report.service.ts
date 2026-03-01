import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { ScanRecord } from '../common/interfaces/scan.interface';
import {
  Vuln,
  VulnType,
  VulnSeverity,
} from '../common/interfaces/vuln.interface';
import { FuzzResult } from '../modules-bridge/fuzzer-client.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ReportService {
  private readonly logger = new Logger(ReportService.name);
  private readonly reportsDir = path.join(process.cwd(), 'reports');

  constructor() {
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, { recursive: true });
    }
  }

  buildVuln(scanId: string, url: string, result: FuzzResult): Vuln {
    return {
      id: uuidv4(),
      scanId,
      url,
      param: result.targetParam,
      payload: result.payload,
      type: this.mapType(result.type),
      severity: result.evidence.browserAlertTriggered
        ? VulnSeverity.HIGH
        : VulnSeverity.MEDIUM,
      reflected: result.reflected,
      executed: result.executed,
      evidence: {
        responseCode: result.evidence.responseCode,
        reflectionPosition: result.evidence.reflectionPosition,
        browserAlertTriggered: result.evidence.browserAlertTriggered,
      },
      discoveredAt: new Date(),
    };
  }

  async generate(
    scanId: string,
    scan: ScanRecord,
    vulns: Vuln[],
    formats: string[],
  ): Promise<string> {
    const reportBase = path.join(this.reportsDir, scanId);

    if (formats.includes('json')) {
      const json = JSON.stringify({ scanId, scan, vulns }, null, 2);
      fs.writeFileSync(`${reportBase}.json`, json, 'utf-8');
    }

    if (formats.includes('html')) {
      const html = this.renderHtml(scan, vulns);
      fs.writeFileSync(`${reportBase}.html`, html, 'utf-8');
    }

    this.logger.log(`report generated for scanId=${scanId} formats=${formats.join(',')}`);
    return `/reports/${scanId}.html`;
  }

  private renderHtml(scan: ScanRecord, vulns: Vuln[]): string {
    const rows = vulns
      .map(
        (v) => `
        <tr>
          <td>${v.param}</td>
          <td><code>${this.esc(v.payload)}</code></td>
          <td>${v.type}</td>
          <td class="sev-${v.severity.toLowerCase()}">${v.severity}</td>
          <td>${v.executed ? '✅' : '❌'}</td>
        </tr>`,
      )
      .join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>RedSentinel Report — ${this.esc(scan.url)}</title>
  <style>
    body { font-family: monospace; background: #0d0d0d; color: #e0e0e0; padding: 2rem; }
    h1 { color: #ff4455; }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    th, td { border: 1px solid #333; padding: 0.5rem 1rem; text-align: left; }
    th { background: #1a1a1a; }
    .sev-high { color: #ff4455; font-weight: bold; }
    .sev-medium { color: #ffaa00; }
    .sev-low { color: #88cc00; }
    code { background: #1a1a1a; padding: 0.1rem 0.4rem; border-radius: 3px; }
    .meta { color: #888; margin-bottom: 2rem; }
  </style>
</head>
<body>
  <h1>🔴 RedSentinel XSS Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> ${this.esc(scan.url)}</p>
    <p><strong>Scan ID:</strong> ${scan.id}</p>
    <p><strong>Status:</strong> ${scan.status}</p>
    <p><strong>Completed:</strong> ${scan.completedAt?.toISOString() ?? 'N/A'}</p>
    <p><strong>Vulnerabilities found:</strong> ${vulns.length}</p>
  </div>
  ${
    vulns.length === 0
      ? '<p style="color:#88cc00">✅ No vulnerabilities found.</p>'
      : `<table>
    <thead>
      <tr><th>Param</th><th>Payload</th><th>Type</th><th>Severity</th><th>JS Executed</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`
  }
</body>
</html>`;
  }

  private mapType(raw: string): VulnType {
    if (raw === 'dom_xss') return VulnType.DOM_XSS;
    if (raw === 'stored_xss') return VulnType.STORED_XSS;
    return VulnType.REFLECTED_XSS;
  }

  private esc(s: string): string {
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

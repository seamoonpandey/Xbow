"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { getScan, cancelScan, getReportFormats, getReportDownloadUrl, regenerateReport } from "@/lib/api";
import type {
  Scan,
  Vuln,
  ReportFormats,
  ProgressEvent,
  FindingEvent,
  CompleteEvent,
  ErrorEvent,
} from "@/lib/types";
import { ScanStatus } from "@/lib/types";
import { StatusBadge, ProgressBar, Card, StatCard } from "@/components/ui";
import { VulnList } from "@/components/vuln-list";
import { useScanSocket } from "@/hooks/use-scan-socket";
import {
  ArrowLeft,
  Download,
  XCircle,
  AlertTriangle,
  Clock,
  Wifi,
  Bug,
  RefreshCw,
  ListTodo,
} from "lucide-react";
import { ScannerLogViewer } from "@/components/scanner-log/scanner-log-viewer";

function formatDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.floor(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [reports, setReports] = useState<ReportFormats | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [regenMsg, setRegenMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const fetchScan = useCallback(async () => {
    try {
      const data = await getScan(scanId);
      setScan(data);
      setVulns(data.vulns ?? []);

      if (data.status === ScanStatus.DONE) {
        try {
          const r = await getReportFormats(scanId);
          setReports(r);
        } catch {
          /* report not yet ready */
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  /* ── websocket handlers ──────────────────────────── */

  const handleProgress = useCallback((e: ProgressEvent) => {
    setScan((prev) =>
      prev ? { ...prev, progress: e.progress, phase: e.phase, status: statusFromPhase(e.phase) } : prev,
    );
    setMessage(e.message);
  }, []);

  const handleFinding = useCallback((e: FindingEvent) => {
    if (e.vuln) setVulns((prev) => [...prev, e.vuln as Vuln]);
  }, []);

  const handleComplete = useCallback(
    (e: CompleteEvent) => {
      setScan((prev) =>
        prev ? { ...prev, status: ScanStatus.DONE, progress: 100 } : prev,
      );
      setMessage(
        `scan complete — ${e.summary.vulnsFound} vulns in ${formatDuration(e.summary.durationMs)}`,
      );
      getReportFormats(scanId)
        .then(setReports)
        .catch(() => {});
    },
    [scanId],
  );

  const handleError = useCallback((e: ErrorEvent) => {
    setScan((prev) =>
      prev ? { ...prev, status: ScanStatus.FAILED, error: e.message } : prev,
    );
    setMessage(e.message);
  }, []);

  const { connected } = useScanSocket({
    scanId,
    onProgress: handleProgress,
    onFinding: handleFinding,
    onComplete: handleComplete,
    onError: handleError,
  });

  /* ── cancel handler ──────────────────────────────── */

  const handleCancel = async () => {
    try {
      await cancelScan(scanId);
      setScan((prev) =>
        prev ? { ...prev, status: ScanStatus.CANCELLED } : prev,
      );
    } catch {
      /* ignore */
    }
  };

  const handleRegenerate = async () => {
    setRegenerating(true);
    setRegenMsg(null);
    try {
      const updated = await regenerateReport(scanId);
      setReports(updated);
      setRegenMsg({ ok: true, text: `Reports regenerated — ${updated.formats.join(", ").toUpperCase()}` });
    } catch (err: unknown) {
      setRegenMsg({ ok: false, text: err instanceof Error ? err.message : "Regeneration failed" });
    } finally {
      setRegenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-slate-500">
        Loading...
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-4 text-slate-500">
        <p>{error || "Scan not found"}</p>
        <Link href="/" className="text-sm text-pink-600 hover:underline">
          Back to dashboard
        </Link>
      </div>
    );
  }

  const isActive =
    scan.status !== ScanStatus.DONE &&
    scan.status !== ScanStatus.FAILED &&
    scan.status !== ScanStatus.CANCELLED;

  const duration =
    scan.completedAt && scan.createdAt
      ? formatDuration(
          new Date(scan.completedAt).getTime() -
            new Date(scan.createdAt).getTime(),
        )
      : "—";

  return (
    <div className="space-y-8">
      {/* ── back + header ───────────────────────────── */}
      <div>
        <Link
          href="/"
          className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft size={14} /> Dashboard
        </Link>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-900">
              Scan Detail
            </h1>
            <p className="mt-1 font-mono text-sm text-slate-500">{scan.url}</p>
            <p className="mt-0.5 text-xs text-slate-400">ID: {scan.id}</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs">
              <Wifi
                size={12}
                className={connected ? "text-emerald-600" : "text-red-600"}
              />
              <span
                className={connected ? "text-emerald-600" : "text-red-600"}
              >
                {connected ? "Live" : "Offline"}
              </span>
            </div>
            <StatusBadge status={scan.status} />
            {isActive && (
              <button
                onClick={handleCancel}
                className="flex items-center gap-1 rounded-lg border border-red-200 px-3 py-1.5 text-xs text-red-600 transition-colors hover:bg-red-50"
              >
                <XCircle size={12} /> Cancel
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── progress ────────────────────────────────── */}
      {isActive && (
        <Card>
          <ProgressBar value={scan.progress} label={scan.phase ?? "Pending"} active />
          {message && (
            <p className="mt-2 text-xs text-slate-500">{message}</p>
          )}
        </Card>
      )}

      {/* ── stats ───────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          label="Vulnerabilities"
          value={vulns.length}
          icon={<Bug size={20} />}
        />
        <StatCard
          label="Duration"
          value={duration}
          icon={<Clock size={20} />}
        />
        <StatCard
          label="Status"
          value={scan.status}
          icon={<AlertTriangle size={20} />}
        />
      </div>

            {/* ── reports ─────────────────────────────────── */}
      {scan.status === ScanStatus.DONE && (
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900">Reports</h2>

            {/* Regenerate button — amber when something is broken/missing, muted otherwise */}
            {(() => {
              const hasBroken =
                reports === null ||
                reports.formats.length === 0 ||
                (reports.broken && reports.broken.length > 0) ||
                !reports.formats.includes("html") ||
                !reports.formats.includes("pdf");
              return (
                <button
                  onClick={handleRegenerate}
                  disabled={regenerating}
                  className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                    hasBroken
                      ? "border-amber-200 text-amber-600 hover:bg-amber-50"
                      : "border-slate-200 text-slate-500 hover:border-slate-300 hover:text-slate-900"
                  }`}
                >
                  <RefreshCw size={12} className={regenerating ? "animate-spin" : ""} />
                  {regenerating ? "Regenerating…" : "Regenerate Reports"}
                </button>
              );
            })()}
          </div>

          {/* Feedback banner */}
          {regenMsg && (
            <p className={`mb-3 rounded-md px-3 py-2 text-xs border ${
              regenMsg.ok
                ? "bg-emerald-50 text-emerald-600 border-emerald-100"
                : "bg-red-50 text-red-600 border-red-100"
            }`}>
              {regenMsg.text}
            </p>
          )}

          {reports && reports.formats.length > 0 ? (
            <div className="flex flex-wrap gap-3">
              {reports.formats.map((fmt) => {
                const isBroken = reports.broken?.includes(fmt);
                return isBroken ? (
                  <div
                    key={fmt}
                    className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600"
                    title="This report file is empty or corrupt — click Regenerate Reports"
                  >
                    <AlertTriangle size={14} />
                    {fmt.toUpperCase()} (broken)
                  </div>
                ) : (
                  <a
                    key={fmt}
                    href={getReportDownloadUrl(scanId, fmt)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-2 text-sm text-slate-600 transition-colors hover:border-pink-300 hover:text-pink-600 hover:bg-pink-50"
                  >
                    <Download size={14} />
                    {fmt.toUpperCase()}
                  </a>
                );
              })}
            </div>
          ) : (
            !regenerating && (
              <p className="text-sm text-slate-500">
                No reports found. Click <span className="text-amber-600 font-medium">Regenerate Reports</span> to create them from the saved scan data.
              </p>
            )
          )}
        </Card>
      )}

      {/* ── scanner log ────────────────────────────── */}
      <Card>
        <div className="mb-4 flex items-center gap-2">
          <ListTodo size={16} className="text-pink-500" />
          <h2 className="text-lg font-semibold text-slate-900">
            Scanner Log
          </h2>
        </div>
        <ScannerLogViewer scanId={scanId} />
      </Card>



      {/* ── vulns ───────────────────────────────────── */}
      <Card>
        <h2 className="mb-3 text-lg font-semibold text-slate-900">
          Findings ({vulns.length})
        </h2>
        <VulnList vulns={vulns} />
      </Card>

      {/* ── scan config ─────────────────────────────── */}
      <Card>
        <h2 className="mb-3 text-lg font-semibold text-slate-900">
          Configuration
        </h2>
        <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          {Object.entries(scan.options).map(([key, val]) => (
            <div key={key}>
              <p className="text-xs text-slate-500">{key}</p>
              <p className="font-mono text-slate-700">
                {Array.isArray(val) ? val.join(", ") : String(val)}
              </p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

/* map phase string back to an approximate status */
function statusFromPhase(phase: string): ScanStatus {
  switch (phase) {
    case "CRAWL":
      return ScanStatus.CRAWLING;
    case "CONTEXT":
      return ScanStatus.ANALYZING;
    case "PAYLOAD_GEN":
      return ScanStatus.GENERATING;
    case "FUZZ":
      return ScanStatus.FUZZING;
    case "REPORT":
      return ScanStatus.REPORTING;
    default:
      return ScanStatus.PENDING;
  }
}

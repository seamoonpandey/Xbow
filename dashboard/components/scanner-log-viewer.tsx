"use client";

import { useState, useEffect, useCallback } from "react";
import { getScannerLog } from "@/lib/api";
import type { ScannerLog, ScannerLogEntry } from "@/lib/api";
import { Spinner } from "@/components/ui";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Link2,
  Bug,
  Shield,
  Globe,
  FileText,
  Layers,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
} from "lucide-react";

/* ── helpers ───────────────────────────────────────────────── */

function formatDuration(ms?: number): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
}

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/* ── phase config ──────────────────────────────────────────── */

interface PhaseConfig {
  label: string;
  icon: React.ReactNode;
  color: string;
  bg: string;
  border: string;
  dot: string;
}

const PHASE_CONFIG: Record<string, PhaseConfig> = {
  AUTH: {
    label: "Authentication",
    icon: <Shield size={14} />,
    color: "text-violet-600",
    bg: "bg-violet-50",
    border: "border-violet-200",
    dot: "bg-violet-500",
  },
  CRAWL: {
    label: "Crawl",
    icon: <Globe size={14} />,
    color: "text-pink-600",
    bg: "bg-pink-50",
    border: "border-pink-200",
    dot: "bg-pink-500",
  },
  CONTEXT: {
    label: "Context Analysis",
    icon: <Layers size={14} />,
    color: "text-blue-600",
    bg: "bg-blue-50",
    border: "border-blue-200",
    dot: "bg-blue-500",
  },
  PAYLOAD_GEN: {
    label: "Payload Generation",
    icon: <FileText size={14} />,
    color: "text-amber-600",
    bg: "bg-amber-50",
    border: "border-amber-200",
    dot: "bg-amber-500",
  },
  FUZZ: {
    label: "Fuzzing",
    icon: <Bug size={14} />,
    color: "text-orange-600",
    bg: "bg-orange-50",
    border: "border-orange-200",
    dot: "bg-orange-500",
  },
  REPORT: {
    label: "Report",
    icon: <FileText size={14} />,
    color: "text-emerald-600",
    bg: "bg-emerald-50",
    border: "border-emerald-200",
    dot: "bg-emerald-500",
  },
  FAIL: {
    label: "Failed",
    icon: <XCircle size={14} />,
    color: "text-red-600",
    bg: "bg-red-50",
    border: "border-red-200",
    dot: "bg-red-500",
  },
};

function getPhaseConfig(phase: string): PhaseConfig {
  return (
    PHASE_CONFIG[phase] ?? {
      label: phase,
      icon: <Play size={14} />,
      color: "text-slate-600",
      bg: "bg-slate-50",
      border: "border-slate-200",
      dot: "bg-slate-400",
    }
  );
}

/* ── single entry row ──────────────────────────────────────── */

function EntryRow({
  entry,
  isLast,
}: {
  entry: ScannerLogEntry;
  isLast: boolean;
}) {
  const cfg = getPhaseConfig(entry.phase);
  const details = entry.details;
  const hasDetails = details != null && Object.keys(details).length > 0;
  const [expanded, setExpanded] = useState(
    hasDetails &&
      (details?.targets || details?.allUrls || details?.forms || details?.formCount != null),
  );

  return (
    <div className="relative pl-10 pb-3 group">
      {/* Timeline connector line */}
      {!isLast && (
        <div className="absolute left-4.25 top-6 bottom-0 w-px bg-slate-200 group-hover:bg-slate-300 transition-colors" />
      )}

      {/* Dot */}
      <div
        className={`absolute left-3 top-1.25 size-2.25 rounded-full ring-2 ring-white ${cfg.dot}`}
      />

      {/* Entry content */}
      <div className="min-w-0">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`shrink-0 ${cfg.color}`}>{cfg.icon}</span>
            <span className="text-xs font-medium text-slate-700 truncate">
              {entry.message}
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {entry.durationMs != null && entry.durationMs > 0 && (
              <span className="flex items-center gap-1 text-[10px] font-mono text-slate-400 whitespace-nowrap">
                <Clock size={10} />
                {formatDuration(entry.durationMs)}
              </span>
            )}
            <span className="text-[10px] font-mono text-slate-400 whitespace-nowrap">
              {formatTimestamp(entry.timestamp)}
            </span>
            {hasDetails && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="p-0.5 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-600 transition-colors"
              >
                {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              </button>
            )}
          </div>
        </div>

        {/* Expandable details */}
        {expanded && hasDetails && (
          <div className="mt-2 ml-0 space-y-2">
            {/* URL targets listing */}
            {details?.targets && Array.isArray(details.targets) && (
              <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
                <div className="px-3 py-2 bg-slate-50 border-b border-slate-200 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Target URLs with Parameters
                </div>
                <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
                  {(details.targets as Array<{ url: string; paramCount: number; params: string[] }>).map((t, idx) => (
                    <div key={idx} className="px-3 py-2 hover:bg-slate-50 transition-colors">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <Link2 size={10} className="text-slate-400 shrink-0" />
                          <span className="text-xs font-mono text-slate-700 truncate">{t.url}</span>
                        </div>
                        <span className="shrink-0 rounded-full bg-blue-50 text-blue-600 text-[10px] font-bold px-2 py-0.5">
                          {t.paramCount} param{t.paramCount !== 1 ? "s" : ""}
                        </span>
                      </div>
                      {t.params.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {t.params.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-mono text-slate-600"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* All crawled URLs */}
            {details?.allUrls && Array.isArray(details.allUrls) && (
              <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
                <div className="px-3 py-2 bg-slate-50 border-b border-slate-200 text-[10px] font-semibold text-slate-500 uppercase tracking-wider flex items-center justify-between">
                  <span>Crawled URLs ({(details.allUrls as string[]).length})</span>
                  <button
                    onClick={() => {
                      const el = document.getElementById(`urls-list-${entry.timestamp}`);
                      if (el) el.classList.toggle("max-h-96");
                    }}
                    className="text-[10px] text-blue-500 hover:text-blue-700"
                  >
                    Toggle list
                  </button>
                </div>
                <div
                  id={`urls-list-${entry.timestamp}`}
                  className="max-h-24 overflow-y-auto divide-y divide-slate-100"
                >
                  {(details.allUrls as string[]).map((url, idx) => (
                    <div key={idx} className="px-3 py-1.5 hover:bg-slate-50 flex items-center gap-2">
                      <span className="text-[10px] font-mono text-slate-500">{idx + 1}.</span>
                      <span className="text-[11px] font-mono text-slate-700 truncate">{url}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Forms discovered */}
            {details?.forms && Array.isArray(details.forms) && (
              <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
                <div className="px-3 py-2 bg-slate-50 border-b border-slate-200 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Discovered Forms ({(details.forms as Array<unknown>).length})
                </div>
                <div className="divide-y divide-slate-100 max-h-48 overflow-y-auto">
                  {(details.forms as Array<{ sourceUrl?: string; action?: string; method?: string; fields?: string[] }>).map((f, idx) => (
                    <div key={idx} className="px-3 py-2 hover:bg-slate-50">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="rounded bg-orange-100 text-orange-600 px-1.5 py-0.5 text-[10px] font-bold uppercase">
                          {f.method || "GET"}
                        </span>
                        <span className="font-mono text-slate-600 truncate">{f.action || f.sourceUrl || "—"}</span>
                      </div>
                      {f.fields && f.fields.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {f.fields.map((field) => (
                            <span
                              key={field}
                              className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-mono text-slate-600"
                            >
                              {field}
                            </span>
                          ))}
                        </div>
                      )}
                      {f.sourceUrl && (
                        <div className="mt-1 text-[10px] text-slate-400 truncate">
                          Source: {f.sourceUrl}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Per-URL summary details */}
            {details?.url && (
              <div className="flex flex-wrap gap-2">
                {details.paramCount != null && (
                  <span className="rounded-full bg-blue-50 text-blue-600 px-2 py-0.5 text-[10px] font-medium">
                    {(details.paramCount as number)} params
                  </span>
                )}
                {details.payloadsTested != null && (details.payloadsTested as number) > 0 && (
                  <span className="rounded-full bg-amber-50 text-amber-600 px-2 py-0.5 text-[10px] font-medium">
                    {(details.payloadsTested as number)} payloads
                  </span>
                )}
                {details.vulnsFound != null && (details.vulnsFound as number) > 0 && (
                  <span className="rounded-full bg-red-50 text-red-600 px-2 py-0.5 text-[10px] font-medium">
                    {(details.vulnsFound as number)} vulns
                  </span>
                )}
                {details.urlDurationMs != null && (
                  <span className="rounded-full bg-slate-100 text-slate-500 px-2 py-0.5 text-[10px] font-medium">
                    {formatDuration(details.urlDurationMs as number)}
                  </span>
                )}
                {details.mode && (
                  <span className="rounded-full bg-purple-50 text-purple-600 px-2 py-0.5 text-[10px] font-medium uppercase">
                    {(details.mode as string)}
                  </span>
                )}
              </div>
            )}

            {/* Form detail badges */}
            {details?.sourceUrl && (
              <div className="flex flex-wrap gap-2">
                <span className="rounded-full bg-orange-50 text-orange-600 px-2 py-0.5 text-[10px] font-medium">
                  Form: {(details.sourceUrl as string).split("/").pop() || "—"}
                </span>
                {details.payloadsTested != null && (details.payloadsTested as number) > 0 && (
                  <span className="rounded-full bg-amber-50 text-amber-600 px-2 py-0.5 text-[10px] font-medium">
                    {(details.payloadsTested as number)} payloads
                  </span>
                )}
                {details.vulnsFound != null && (details.vulnsFound as number) > 0 && (
                  <span className="rounded-full bg-red-50 text-red-600 px-2 py-0.5 text-[10px] font-medium">
                    {(details.vulnsFound as number)} vulns
                  </span>
                )}
                {details.formDurationMs != null && (
                  <span className="rounded-full bg-slate-100 text-slate-500 px-2 py-0.5 text-[10px] font-medium">
                    {formatDuration(details.formDurationMs as number)}
                  </span>
                )}
              </div>
            )}

            {/* Tested fields */}
            {details?.testedFields && Array.isArray(details.testedFields) && (
              <div className="flex flex-wrap gap-1">
                {(details.testedFields as string[]).map((f) => (
                  <span key={f} className="rounded bg-orange-100 text-orange-600 px-1.5 py-0.5 text-[10px] font-mono">
                    {f}
                  </span>
                ))}
              </div>
            )}

            {/* Generic key-value pairs */}
            {Object.entries(details as Record<string, unknown>)
              .filter(
                ([key]) =>
                  !["url", "params", "targets", "allUrls", "forms", "urlIndex", "totalUrls",
                    "payloadsTested", "vulnsFound", "urlDurationMs", "mode", "sourceUrl", "actionUrl",
                    "fields", "testedFields", "formDurationMs", "paramCount", "payloadCount",
                    "totalPayloads", "uniquePayloads", "contextsCount", "reflectingParams",
                    "totalUrls", "totalParams", "waf", "formCount", "forms", "totalPayloadsUsed",
                    "totalTargets"].includes(key) &&
                  details?.[key] != null &&
                  !Array.isArray(details[key]) &&
                  typeof details[key] !== "object"
              )
              .slice(0, 8)
              .map(([key, val]) => (
                <div key={key} className="flex items-center gap-2 text-[10px]">
                  <span className="text-slate-400 font-medium capitalize">{key.replace(/([A-Z])/g, " $1")}:</span>
                  <span className="font-mono text-slate-600">{String(val)}</span>
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── phase group ───────────────────────────────────────────── */

function PhaseGroup({
  phase,
  entries,
  allEntries,
}: {
  phase: string;
  entries: ScannerLogEntry[];
  allEntries: ScannerLogEntry[];
}) {
  const cfg = getPhaseConfig(phase);
  const [collapsed, setCollapsed] = useState(false);

  // Calculate phase stats
  const totalDuration = entries.reduce(
    (sum, e) => sum + (e.durationMs ?? 0),
    0,
  );
  const urlCount = entries.filter((e) => e.details?.url).length;
  const payloadCount = entries.reduce(
    (sum, e) => sum + ((e.details?.payloadsTested as number) ?? (e.details?.totalPayloads as number) ?? 0),
    0,
  );
  const vulnCount = entries.reduce(
    (sum, e) => sum + ((e.details?.vulnsFound as number) ?? 0),
    0,
  );
  const formCount = entries.filter((e) => e.details?.sourceUrl).length;


  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      {/* Phase header */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className={`w-full flex items-center justify-between px-4 py-3 ${cfg.bg} border-b border-slate-200 hover:opacity-90 transition-opacity`}
      >
        <div className="flex items-center gap-2">
          <span className={cfg.color}>{cfg.icon}</span>
          <span className={`text-xs font-bold uppercase tracking-wider ${cfg.color}`}>
            {cfg.label}
          </span>
          <span className="text-[10px] font-mono text-slate-400">
            {entries.length} step{entries.length !== 1 ? "s" : ""}
          </span>
        </div>
        <div className="flex items-center gap-3">
          {/* Phase stats badges */}
          {urlCount > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1 rounded-full bg-white/80 px-2 py-0.5 text-[10px] font-medium text-slate-500">
              <Link2 size={10} />
              {urlCount}
            </span>
          )}
          {payloadCount > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1 rounded-full bg-white/80 px-2 py-0.5 text-[10px] font-medium text-amber-600">
              <FileText size={10} />
              {payloadCount}
            </span>
          )}
          {vulnCount > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1 rounded-full bg-white/80 px-2 py-0.5 text-[10px] font-medium text-red-600">
              <Bug size={10} />
              {vulnCount}
            </span>
          )}
          {formCount > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1 rounded-full bg-white/80 px-2 py-0.5 text-[10px] font-medium text-orange-600">
              <Layers size={10} />
              {formCount}
            </span>
          )}
          {totalDuration > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1 text-[10px] font-mono text-slate-400">
              <Clock size={10} />
              {formatDuration(totalDuration)}
            </span>
          )}
          <ChevronDown
            size={14}
            className={`text-slate-400 transition-transform duration-200 ${
              collapsed ? "-rotate-90" : ""
            }`}
          />
        </div>
      </button>

      {/* Entries list */}
      {!collapsed && (
        <div className="px-4 py-3">
          {entries.map((entry, i) => {
            const globalIdx = allEntries.indexOf(entry);
            const isLastInAll = globalIdx === allEntries.length - 1;
            return (
              <EntryRow
                key={`${entry.timestamp}-${i}`}
                entry={entry}
                isLast={isLastInAll}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ── scanner status banner ─────────────────────────────────── */

function StatusBanner({ log }: { log: ScannerLog }) {
  const isComplete = log.status === "COMPLETED";
  const isFailed = log.status === "FAILED";

  return (
    <div
      className={`rounded-xl border p-4 flex items-center justify-between ${
        isComplete
          ? "bg-emerald-50 border-emerald-200 text-emerald-700"
          : isFailed
          ? "bg-red-50 border-red-200 text-red-700"
          : "bg-blue-50 border-blue-200 text-blue-700"
      }`}
    >
      <div className="flex items-center gap-3">
        {isComplete ? (
          <CheckCircle2 size={20} />
        ) : isFailed ? (
          <XCircle size={20} />
        ) : (
          <AlertTriangle size={20} />
        )}
        <div>
          <p className="text-sm font-semibold">
            {isComplete ? "Scan Completed" : isFailed ? "Scan Failed" : "Scan In Progress"}
          </p>
          <p className="text-xs opacity-80 mt-0.5">
            {log.entries.length} log entr{log.entries.length !== 1 ? "ies" : "y"} —{" "}
            {log.completedAt
              ? `Completed at ${formatTimestamp(log.completedAt)}`
              : log.startedAt
              ? `Started at ${formatTimestamp(log.startedAt)}`
              : ""}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2 text-xs">
        <span className="font-mono opacity-75">{log.targetUrl}</span>
      </div>
    </div>
  );
}

/* ── main component ────────────────────────────────────────── */

export function ScannerLogViewer({ scanId }: { scanId: string }) {
  const [log, setLog] = useState<ScannerLog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLog = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getScannerLog(scanId);
      setLog(data);
      setError(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "failed to load scanner log";
      // 404 means log not yet available — that's normal for running scans
      if (msg.includes("404") || msg.includes("not yet available")) {
        setError("log-not-ready");
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchLog();
  }, [fetchLog]);

  if (loading) {
    return (
      <div className="flex h-32 items-center justify-center gap-2 text-slate-500">
        <Spinner size={16} />
        <span className="text-xs">Loading scanner log...</span>
      </div>
    );
  }

  if (error === "log-not-ready") {
    return (
      <div className="flex h-32 flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-slate-200 bg-slate-50/50">
        <Clock size={20} className="text-slate-300" />
        <p className="text-xs text-slate-500">
          Scanner log will appear here once the scan completes.
        </p>
      </div>
    );
  }

  if (error || !log) {
    return (
      <div className="flex h-32 items-center justify-center">
        <p className="text-xs text-red-500">{error || "No scanner log available"}</p>
      </div>
    );
  }

  // Group entries by phase
  const phaseOrder = ["AUTH", "CRAWL", "CONTEXT", "PAYLOAD_GEN", "FUZZ", "REPORT", "FAIL"];
  const grouped = new Map<string, ScannerLogEntry[]>();
  for (const entry of log.entries) {
    const p = entry.phase;
    if (!grouped.has(p)) grouped.set(p, []);
    grouped.get(p)!.push(entry);
  }

  // Sort phase groups in order
  const sortedGroups = phaseOrder
    .filter((p) => grouped.has(p))
    .map((p) => ({ phase: p, entries: grouped.get(p)! }));

  // Also include any other phases not in the order
  for (const [phase, entries] of grouped) {
    if (!phaseOrder.includes(phase)) {
      sortedGroups.push({ phase, entries });
    }
  }

  return (
    <div className="space-y-4">
      {/* Status banner */}
      <StatusBanner log={log} />

      {/* Timeline stats summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-slate-200 bg-white p-3 text-center">
          <p className="text-2xl font-bold text-slate-900">{log.entries.length}</p>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">Log Entries</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-3 text-center">
          <p className="text-2xl font-bold text-slate-900">{sortedGroups.length}</p>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">Phases</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-3 text-center">
          <p className="text-2xl font-bold text-emerald-600">
            {log.entries.reduce((sum, e) => sum + ((e.details?.vulnsFound as number) ?? 0), 0)}
          </p>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">Vulns Found</p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-3 text-center">
          <p className="text-2xl font-bold text-amber-600">
            {log.entries.reduce((sum, e) => sum + ((e.details?.payloadsTested as number) ?? (e.details?.totalPayloads as number) ?? 0), 0)}
          </p>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">Payloads Used</p>
        </div>
      </div>

      {/* Phase groups */}
      <div className="space-y-3">
        {sortedGroups.map(({ phase, entries }) => (
          <PhaseGroup
            key={phase}
            phase={phase}
            entries={entries}
            allEntries={log.entries}
          />
        ))}
      </div>
    </div>
  );
}

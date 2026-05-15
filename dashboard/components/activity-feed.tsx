"use client";

import useSWR from "swr";
import Link from "next/link";
import { listScans, getAuditLogs } from "@/lib/api";
import type { AuditLogEntry } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { ScanStatus } from "@/lib/types";
import { Card, Spinner, StatusBadge } from "@/components/ui";
import { Activity, ArrowRight, Clock3, Layers3, MessageSquareText } from "lucide-react";

type ActivityItem = {
  scan: Scan;
  logs: AuditLogEntry[];
};

export function ActivityFeed() {
  const { data = [], isLoading } = useSWR<ActivityItem[]>(
    "activity-feed",
    async () => {
      const scans = await listScans(1, 8);
      const recentScans = scans.slice(0, 5);

      return Promise.all(
        recentScans.map(async (scan) => {
          try {
            const result = await getAuditLogs(scan.id);
            return {
              scan,
              logs: result.logs.slice(-6),
            };
          } catch {
            return { scan, logs: [] };
          }
        }),
      );
    },
    { fallbackData: [] },
  );

  const totalEntries = data.reduce((sum, item) => sum + item.logs.length, 0);
  const activeScans = data.filter((item) => item.scan.status !== ScanStatus.DONE).length;

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={20} />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold text-slate-900">
            <Activity size={24} className="text-pink-500" />
            Activity
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Audit trail from the latest scans and operational events.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Metric label="Scans" value={data.length} />
          <Metric label="Active" value={activeScans} />
          <Metric label="Events" value={totalEntries} />
        </div>
      </div>

      {data.length === 0 ? (
        <Card className="flex min-h-64 flex-col items-center justify-center gap-3 text-center">
          <MessageSquareText size={28} className="text-slate-300" />
          <div>
            <p className="text-sm font-medium text-slate-700">No recent activity</p>
            <p className="mt-1 text-sm text-slate-500">
              Run a scan to start collecting audit events.
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-4">
          {data.map((item) => (
            <Card key={item.scan.id} className="space-y-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-3">
                    <Link href={`/scan/${item.scan.id}`} className="text-base font-semibold text-slate-900 hover:text-pink-600">
                      {item.scan.url}
                    </Link>
                    <StatusBadge status={item.scan.status} />
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-slate-500">
                    <span className="flex items-center gap-1.5">
                      <Clock3 size={12} />
                      {new Date(item.scan.createdAt).toLocaleString()}
                    </span>
                    <span className="flex items-center gap-1.5">
                      <Layers3 size={12} />
                      {item.logs.length} event{item.logs.length === 1 ? "" : "s"}
                    </span>
                  </div>
                </div>
                <Link href={`/scan/${item.scan.id}`} className="inline-flex items-center gap-1.5 text-sm font-medium text-pink-600 hover:text-pink-700">
                  View scan <ArrowRight size={14} />
                </Link>
              </div>

              {item.logs.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50/70 px-4 py-6 text-sm text-slate-500">
                  No audit logs were returned for this scan.
                </div>
              ) : (
                <div className="space-y-2">
                  {item.logs.map((log) => (
                    <div key={log.id} className="flex flex-col gap-2 rounded-lg border border-slate-200 bg-slate-50/50 px-4 py-3 md:flex-row md:items-center md:justify-between">
                      <div>
                        <div className="flex items-center gap-2 text-sm font-medium text-slate-800">
                          <span className="rounded-full bg-pink-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-pink-600">
                            {log.phase}
                          </span>
                          <span>{log.message}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500">
                          Step {log.step}
                        </p>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-slate-500">
                        {log.durationMs != null && (
                          <span>{log.durationMs}ms</span>
                        )}
                        <span>{new Date(log.createdAt).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold text-slate-900">
        {value}
      </div>
    </div>
  );
}

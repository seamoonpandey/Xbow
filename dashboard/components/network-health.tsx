"use client";

import useSWR from "swr";
import { getHealth } from "@/lib/api";
import type { HealthReport } from "@/lib/types";
import { Card, Spinner } from "@/components/ui";
import { Globe2, HeartPulse, ServerCrash, ShieldCheck, Activity } from "lucide-react";

export function NetworkHealth() {
  const { data, isLoading } = useSWR<HealthReport>("network-health", getHealth, {
    fallbackData: undefined,
  });

  if (isLoading || !data) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={20} />
      </div>
    );
  }

  const healthyCount = data.services.filter((service) => service.status === "up").length;
  const downCount = data.services.filter((service) => service.status === "down").length;

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold text-slate-900">
            <Globe2 size={24} className="text-pink-500" />
            Network
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Live health view across the backend services that power the console.
          </p>
        </div>

        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-medium ${statusStyles[data.status]}`}>
          <HeartPulse size={14} />
          {data.status}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Metric label="Services up" value={healthyCount} icon={<ShieldCheck size={16} />} tone="emerald" />
        <Metric label="Services down" value={downCount} icon={<ServerCrash size={16} />} tone="red" />
        <Metric label="Uptime" value={formatUptime(data.uptime)} icon={<Activity size={16} />} tone="slate" />
      </div>

      <Card className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Service status</h2>
            <p className="text-sm text-slate-500">
              Last checked {new Date(data.timestamp).toLocaleString()}
            </p>
          </div>
          <span className="text-xs font-medium text-slate-400">
            {data.services.length} services
          </span>
        </div>

        <div className="space-y-3">
          {data.services.map((service) => (
            <div key={service.name} className="flex flex-col gap-3 rounded-lg border border-slate-200 bg-slate-50/50 px-4 py-3 md:flex-row md:items-center md:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`size-2 rounded-full ${service.status === "up" ? "bg-emerald-500" : "bg-red-500"}`} />
                  <span className="text-sm font-medium text-slate-900">{service.name}</span>
                </div>
                {service.detail && <p className="mt-1 text-xs text-slate-500">{service.detail}</p>}
              </div>

              <div className="flex items-center gap-3 text-sm text-slate-600">
                <span className={`rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wider ${service.status === "up" ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
                  {service.status}
                </span>
                <span className="font-mono text-xs text-slate-500">{service.latencyMs} ms</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

function Metric({ label, value, icon, tone }: { label: string; value: string | number; icon: React.ReactNode; tone: "emerald" | "red" | "slate"; }) {
  const tones = {
    emerald: "bg-emerald-50 text-emerald-700 border-emerald-200",
    red: "bg-red-50 text-red-700 border-red-200",
    slate: "bg-slate-50 text-slate-700 border-slate-200",
  } as const;

  return (
    <Card className="flex items-center justify-between gap-4 py-4">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{label}</div>
        <div className="mt-1 text-2xl font-semibold text-slate-900">{value}</div>
      </div>
      <div className={`flex size-11 items-center justify-center rounded-xl border ${tones[tone]}`}>
        {icon}
      </div>
    </Card>
  );
}

function formatUptime(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours < 1) return `${minutes}m`;
  return `${hours}h ${minutes % 60}m`;
}

const statusStyles: Record<HealthReport["status"], string> = {
  healthy: "border-emerald-200 bg-emerald-50 text-emerald-700",
  degraded: "border-amber-200 bg-amber-50 text-amber-700",
  unhealthy: "border-red-200 bg-red-50 text-red-700",
};

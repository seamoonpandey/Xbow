"use client";

import { useState, useCallback } from "react";
import useSWR from "swr";
import { listScans, deleteAllScans } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { ScanStatus } from "@/lib/types";
import { NewScanForm } from "@/components/new-scan-form";
import { ScanTable } from "@/components/scan-table";
import { useScanSocket } from "@/hooks/use-scan-socket";
import { Plus, Server, ShieldCheck, Bug, LayoutGrid } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export function ScansOverview({
  title = "Dashboard",
  description = "Overview of your security infrastructure and active tasks.",
  showSummary = true,
  showDrawer = true,
  showClearAll = true,
}: {
  title?: string;
  description?: string;
  showSummary?: boolean;
  showDrawer?: boolean;
  showClearAll?: boolean;
}) {
  const [clearingAll, setClearingAll] = useState(false);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const { data: scans = [], mutate, isLoading } = useSWR<Scan[]>(
    "scans",
    () => listScans(1, 100),
    { fallbackData: [] }
  );

  useScanSocket({
    onProgress: (e) => {
      mutate((prev = []) => prev.map((s) => s.id === e.scanId ? { ...s, progress: e.progress, phase: e.phase } : s), { revalidate: false });
    },
    onComplete: (e) => {
      mutate((prev = []) => prev.map((s) => s.id === e.scanId ? { ...s, status: ScanStatus.DONE, progress: 100 } : s), { revalidate: false });
    },
    onError: (e) => {
      mutate((prev = []) => prev.map((s) => s.id === e.scanId ? { ...s, status: ScanStatus.FAILED, error: e.message } : s), { revalidate: false });
    },
  });

  const handleScanCreated = useCallback((scan: Scan) => {
    mutate(async () => {
      return [scan, ...scans];
    }, {
      optimisticData: [scan, ...scans],
      rollbackOnError: true,
      populateCache: true,
      revalidate: false,
    });
    setIsDrawerOpen(false);
  }, [mutate, scans]);

  const handleClearAll = async () => {
    if (!confirm("Are you sure you want to clear all scans? This cannot be undone.")) return;
    setClearingAll(true);

    mutate(
      async () => {
        await deleteAllScans();
        return [];
      },
      {
        optimisticData: [],
        rollbackOnError: true,
        populateCache: true,
        revalidate: false,
      }
    ).catch((err) => {
      console.error("Failed to clear scans:", err);
    }).finally(() => {
      setClearingAll(false);
    });
  };

  const handleDeleteScan = useCallback((id: string) => {
    mutate(
      async () => {
        return scans.filter((s) => s.id !== id);
      },
      {
        optimisticData: scans.filter((s) => s.id !== id),
        rollbackOnError: true,
        populateCache: true,
        revalidate: false,
      }
    );
  }, [mutate, scans]);

  const activeScans = scans.filter(
    (s) => s.status !== ScanStatus.DONE && s.status !== ScanStatus.FAILED && s.status !== ScanStatus.CANCELLED,
  ).length;
  const totalVulns = scans.reduce((sum, s) => sum + (s.vulns?.length ?? 0), 0);
  const completedScans = scans.filter((s) => s.status === ScanStatus.DONE).length;

  if (isLoading) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-center gap-4"
        >
          <div className="relative flex size-8 items-center justify-center">
            <div className="absolute inset-0 animate-spin rounded-full border-2 border-pink-500 border-t-transparent" />
          </div>
          <span className="text-sm font-medium text-slate-500">
            Loading data...
          </span>
        </motion.div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="space-y-8"
    >
      <div className="flex flex-col justify-between gap-6 md:flex-row md:items-center">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold text-slate-900">
            <LayoutGrid size={24} className="text-pink-500" />
            {title}
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            {description}
          </p>
        </div>

        {showDrawer && (
          <button
            onClick={() => setIsDrawerOpen(true)}
            className="flex items-center gap-2 rounded-lg bg-pink-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-pink-700"
          >
            <Plus size={16} />
            New Scan
          </button>
        )}
      </div>

      {showSummary && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <MiniStat label="Active Scans" value={activeScans} status="active" icon={<Server size={18} />} />
          <MiniStat label="Completed" value={completedScans} status="secure" icon={<ShieldCheck size={18} />} />
          <MiniStat label="Vulnerabilities" value={totalVulns} status="danger" icon={<Bug size={18} />} />
        </div>
      )}

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-slate-900">Recent Scans</h2>
          {showClearAll && scans.length > 0 && (
            <button
              onClick={handleClearAll}
              disabled={clearingAll}
              className="text-sm text-slate-500 transition-colors hover:text-red-600"
            >
              {clearingAll ? "Clearing..." : "Clear All"}
            </button>
          )}
        </div>

        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <ScanTable scans={scans} onDelete={handleDeleteScan} />
        </div>
      </div>

      <AnimatePresence>
        {showDrawer && isDrawerOpen && (
          <div className="fixed inset-0 z-60 flex justify-end">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-slate-900/20 backdrop-blur-sm"
              onClick={() => setIsDrawerOpen(false)}
            />
            <motion.div
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ type: "spring", damping: 30, stiffness: 300 }}
              className="relative z-70 flex h-full w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl"
            >
              <div className="flex h-16 items-center justify-between border-b border-slate-100 px-6">
                <span className="text-sm font-semibold text-slate-900">Create New Scan</span>
                <button
                  onClick={() => setIsDrawerOpen(false)}
                  className="rounded-md p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
                >
                  <Plus size={20} className="rotate-45" />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto bg-slate-50/50 p-6">
                <NewScanForm onCreated={handleScanCreated} />
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function MiniStat({ label, value, status, icon }: { label: string; value: string | number; status: string; icon?: React.ReactNode }) {
  const styles = {
    active: { bg: "bg-pink-50", text: "text-pink-600", border: "border-slate-200" },
    secure: { bg: "bg-emerald-50", text: "text-emerald-600", border: "border-slate-200" },
    danger: { bg: "bg-red-50", text: "text-red-600", border: "border-slate-200" },
  };

  const style = styles[status as keyof typeof styles];

  return (
    <div className={`rounded-xl bg-white border ${style.border} p-5 shadow-sm`}>
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium text-slate-500">{label}</span>
        <div className={`rounded-md p-2 ${style.bg} ${style.text}`}>
          {icon}
        </div>
      </div>
      <div className="text-3xl font-semibold text-slate-900">
        {value}
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";
import { createScan } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { Crosshair, Layers, FileSearch } from "lucide-react";

interface NewScanFormProps {
  onCreated: (scan: Scan) => void;
}

export function NewScanForm({ onCreated }: NewScanFormProps) {
  const [url, setUrl] = useState("");
  const [singlePage, setSinglePage] = useState(true);
  const [maxPayloads, setMaxPayloads] = useState(50);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const scan = await createScan(url, {
        singlePage,
        depth: singlePage ? 1 : 3,
        maxPayloadsPerParam: maxPayloads,
        reportFormat: ["html", "json", "pdf"],
      });
      setUrl("");
      onCreated(scan);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="url" className="mb-1 block text-sm text-zinc-400">
          Target URL
        </label>
        <input
          id="url"
          type="url"
          required
          placeholder="https://target.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
        />
      </div>

      {/* ── Scan mode toggle ── */}
      <div>
        <p className="mb-2 text-sm text-zinc-400">Scan mode</p>
        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => setSinglePage(true)}
            className={`flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-sm transition-colors ${
              singlePage
                ? "border-emerald-500 bg-emerald-500/10 text-emerald-300"
                : "border-zinc-700 bg-zinc-800 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            <FileSearch size={15} className="shrink-0" />
            <span>
              <span className="block font-medium">Single page</span>
              <span className="text-xs opacity-70">Fast · exact URL only</span>
            </span>
          </button>
          <button
            type="button"
            onClick={() => setSinglePage(false)}
            className={`flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-sm transition-colors ${
              !singlePage
                ? "border-emerald-500 bg-emerald-500/10 text-emerald-300"
                : "border-zinc-700 bg-zinc-800 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            <Layers size={15} className="shrink-0" />
            <span>
              <span className="block font-medium">Full crawl</span>
              <span className="text-xs opacity-70">Thorough · follows links</span>
            </span>
          </button>
        </div>
      </div>

      <div>
        <label
          htmlFor="maxPayloads"
          className="mb-1 block text-sm text-zinc-400"
        >
          Max payloads / param
        </label>
        <input
          id="maxPayloads"
          type="number"
          min={5}
          max={200}
          value={maxPayloads}
          onChange={(e) => setMaxPayloads(Number(e.target.value))}
          className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm text-zinc-100 outline-none focus:border-emerald-500"
        />
      </div>

      {error && (
        <p className="text-sm text-red-400">{error}</p>
      )}

      <button
        type="submit"
        disabled={loading}
        className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
      >
        <Crosshair size={16} />
        {loading ? "Starting Scan..." : "Start Scan"}
      </button>
    </form>
  );
}

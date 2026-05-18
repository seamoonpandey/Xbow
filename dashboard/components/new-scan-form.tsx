"use client";

import { useState } from "react";
import { createScan, testAuth } from "@/lib/api";
import type { Scan } from "@/lib/types";
import {
  Crosshair,
  Layers,
  FileSearch,
  ShieldAlert,
  Rocket,
  ChevronDown,
  LogIn,
  CheckCircle2,
  XCircle,
  Eye,
  EyeOff,
  Settings2,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface NewScanFormProps {
  onCreated: (scan: Scan) => void;
}

export function NewScanForm({ onCreated }: NewScanFormProps) {
  const [url, setUrl] = useState("");
  const [singlePage, setSinglePage] = useState(true);
  const [maxPayloads, setMaxPayloads] = useState(50);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // ── Advanced options state ────────────────────────────────────
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [loginUrl, setLoginUrl] = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [usernameSelector, setUsernameSelector] = useState("");
  const [passwordSelector, setPasswordSelector] = useState("");
  const [submitSelector, setSubmitSelector] = useState("");
  const [postLoginWaitMs, setPostLoginWaitMs] = useState(3000);
  const [successUrlContains, setSuccessUrlContains] = useState("");

  // ── Test login state ──────────────────────────────────────────
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    status: "idle" | "success" | "error";
    message: string;
  }>({ status: "idle", message: "" });

  const handleTestLogin = async () => {
    if (!loginUrl || !authUsername || !authPassword) {
      setTestResult({
        status: "error",
        message: "Please fill in Login URL, Username, and Password first",
      });
      return;
    }
    setTesting(true);
    setTestResult({ status: "idle", message: "Testing credentials..." });
    try {
      const resp = await testAuth(loginUrl, authUsername, authPassword, {
        usernameSelector: usernameSelector || undefined,
        passwordSelector: passwordSelector || undefined,
        submitSelector: submitSelector || undefined,
        postLoginWaitMs,
        successUrlContains: successUrlContains || undefined,
      });
      if (resp.success) {
        setTestResult({
          status: "success",
          message: ` Login successful! ${resp.cookies ?? 0} cookies captured from ${resp.createdAt ? new Date(resp.createdAt).toLocaleTimeString() : "now"}`,
        });
      } else {
        setTestResult({
          status: "error",
          message: ` Login failed: ${resp.error ?? resp.message ?? "Unknown error"}`,
        });
      }
    } catch (err: unknown) {
      setTestResult({
        status: "error",
        message: ` Connection error: ${err instanceof Error ? err.message : "Unknown error"}`,
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const options: Record<string, unknown> = {
        singlePage,
        depth: singlePage ? 1 : 3,
        maxPayloadsPerParam: maxPayloads,
        reportFormat: ["html", "json", "pdf"],
      };

      if (authEnabled && loginUrl && authUsername && authPassword) {
        options.auth = {
          enabled: true,
          loginUrl,
          username: authUsername,
          password: authPassword,
          usernameSelector: usernameSelector || undefined,
          passwordSelector: passwordSelector || undefined,
          submitSelector: submitSelector || undefined,
          postLoginWaitMs,
          successUrlContains: successUrlContains || undefined,
        };
      }

      const scan = await createScan(url, options);
      setUrl("");
      setTestResult({ status: "idle", message: "" });
      onCreated(scan);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "failed to launch audit");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 outline-none transition-all focus:border-pink-300 focus:ring-2 focus:ring-pink-100";
  const labelClass = "text-xs font-bold text-slate-600 tracking-tight uppercase";

  return (
    <form onSubmit={handleSubmit} className="space-y-8">
      <div className="space-y-3">
        <label htmlFor="url" className="flex items-center gap-2 text-sm font-bold text-slate-800 tracking-tight">
          Target Asset URL
        </label>
        <div className="relative group">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-rose-200 to-pink-300 rounded-xl blur opacity-0 group-hover:opacity-50 transition duration-500 group-focus-within:opacity-100"></div>
          <input
            id="url"
            type="url"
            required
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="relative w-full rounded-xl border border-white/60 bg-white/60 backdrop-blur-md px-5 py-4 text-[15px] font-mono text-slate-900 placeholder-slate-400 outline-none transition-all focus:bg-white focus:border-pink-300 shadow-[0_2px_10px_-4px_rgba(0,0,0,0.05)]"
          />
        </div>
      </div>

      {/* ── Scan mode toggle ── */}
      <div className="space-y-4">
        <p className="text-sm font-bold text-slate-800 tracking-tight">Audit Strategy</p>
        <div className="grid grid-cols-1 gap-3">
          <button
            type="button"
            onClick={() => setSinglePage(true)}
            className={`group relative flex items-center gap-5 rounded-2xl border p-5 text-left transition-all duration-300 ${
              singlePage
                ? "border-pink-200 bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)]"
                : "border-white/50 bg-white/40 hover:bg-white/60 backdrop-blur-md hover:border-white"
            }`}
          >
            <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 ${singlePage ? "bg-pink-100/50 text-pink-600 scale-110" : "bg-slate-100 text-slate-400 group-hover:scale-105"}`}>
              <FileSearch size={22} />
            </div>
            <div>
              <span className={`block text-[15px] font-bold ${singlePage ? "text-pink-600" : "text-slate-600"}`}>Surface Scan</span>
              <span className="text-sm text-slate-500 mt-0.5 block font-medium">Target URL Only</span>
            </div>
          </button>
          
          <button
            type="button"
            onClick={() => setSinglePage(false)}
            className={`group relative flex items-center gap-5 rounded-2xl border p-5 text-left transition-all duration-300 ${
              !singlePage
                ? "border-pink-200 bg-white shadow-[0_8px_30px_rgb(0,0,0,0.04)]"
                : "border-white/50 bg-white/40 hover:bg-white/60 backdrop-blur-md hover:border-white"
            }`}
          >
            <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 ${!singlePage ? "bg-pink-100/50 text-pink-600 scale-110" : "bg-slate-100 text-slate-400 group-hover:scale-105"}`}>
              <Layers size={22} />
            </div>
            <div>
              <span className={`block text-[15px] font-bold ${!singlePage ? "text-pink-600" : "text-slate-600"}`}>Deep Penetration</span>
              <span className="text-sm text-slate-500 mt-0.5 block font-medium">Full Network Probe</span>
            </div>
          </button>
        </div>
      </div>

      <div className="space-y-4">
        <label
          htmlFor="maxPayloads"
          className="flex items-center justify-between text-sm font-bold text-slate-800 tracking-tight"
        >
          <span>Injection Density</span>
          <span className="text-pink-600 bg-pink-100/50 border border-pink-100 px-3 py-1 rounded-lg text-xs font-black tracking-widest">{maxPayloads} REQ/PARAM</span>
        </label>
        <div className="relative pt-2">
          <input
            id="maxPayloads"
            type="range"
            min={5}
            max={200}
            step={5}
            value={maxPayloads}
            onChange={(e) => setMaxPayloads(Number(e.target.value))}
            className="w-full accent-pink-500 h-2.5 bg-slate-200 rounded-full appearance-none cursor-pointer hover:bg-pink-100 transition-colors"
          />
        </div>
      </div>

      {/* ── Advanced Options (collapsible) ────────────────────────── */}
      <div className="rounded-2xl border border-slate-100 bg-white/50 overflow-hidden">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex w-full items-center justify-between px-5 py-4 text-left transition-colors hover:bg-slate-50"
        >
          <span className="flex items-center gap-2 text-sm font-bold text-slate-700">
            <Settings2 size={16} className="text-slate-400" />
            Advanced Options
          </span>
          <motion.div
            animate={{ rotate: showAdvanced ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown size={18} className="text-slate-400" />
          </motion.div>
        </button>

        <AnimatePresence initial={false}>
          {showAdvanced && (
            <motion.div
              key="advanced-content"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25, ease: "easeInOut" }}
              className="overflow-hidden"
            >
              <div className="px-5 pb-5 space-y-5 border-t border-slate-100 pt-4">
                {/* ── Auth toggle ── */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <LogIn size={16} className="text-slate-400" />
                    <span className="text-sm font-semibold text-slate-700">Authentication</span>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={authEnabled}
                    onClick={() => {
                      setAuthEnabled(!authEnabled);
                      if (!authEnabled) setTestResult({ status: "idle", message: "" });
                    }}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-pink-300 focus:ring-offset-2 ${
                      authEnabled ? "bg-pink-500" : "bg-slate-200"
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        authEnabled ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>

                {/* ── Auth fields ── */}
                <AnimatePresence>
                  {authEnabled && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="space-y-4 overflow-hidden"
                    >
                      <div className="space-y-2">
                        <label className={labelClass}>Login URL</label>
                        <input
                          type="url"
                          placeholder="https://target.com/login.php"
                          value={loginUrl}
                          onChange={(e) => setLoginUrl(e.target.value)}
                          className={inputClass}
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-2">
                          <label className={labelClass}>Username</label>
                          <input
                            type="text"
                            placeholder="admin"
                            value={authUsername}
                            onChange={(e) => setAuthUsername(e.target.value)}
                            className={inputClass}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className={labelClass}>Password</label>
                          <div className="relative">
                            <input
                              type={showPassword ? "text" : "password"}
                              placeholder="••••••••"
                              value={authPassword}
                              onChange={(e) => setAuthPassword(e.target.value)}
                              className={`${inputClass} pr-10`}
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                            >
                              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Optional selectors */}
                      <details className="group">
                        <summary className="flex cursor-pointer list-none items-center gap-2 text-xs font-semibold text-slate-500 hover:text-slate-700 transition-colors">
                          <ChevronDown size={14} className="transition-transform group-open:rotate-180" />
                          Custom selectors (optional)
                        </summary>
                        <div className="mt-3 space-y-3 pl-4 border-l-2 border-slate-100">
                          <div className="space-y-1.5">
                            <label className="text-[11px] font-semibold text-slate-500">Username field selector</label>
                            <input
                              type="text"
                              placeholder='input[name="username"]'
                              value={usernameSelector}
                              onChange={(e) => setUsernameSelector(e.target.value)}
                              className={inputClass}
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[11px] font-semibold text-slate-500">Password field selector</label>
                            <input
                              type="text"
                              placeholder='input[name="password"]'
                              value={passwordSelector}
                              onChange={(e) => setPasswordSelector(e.target.value)}
                              className={inputClass}
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-[11px] font-semibold text-slate-500">Submit button selector</label>
                            <input
                              type="text"
                              placeholder='button[type="submit"]'
                              value={submitSelector}
                              onChange={(e) => setSubmitSelector(e.target.value)}
                              className={inputClass}
                            />
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <div className="space-y-1.5">
                              <label className="text-[11px] font-semibold text-slate-500">Post-login wait (ms)</label>
                              <input
                                type="number"
                                min={500}
                                max={30000}
                                step={500}
                                value={postLoginWaitMs}
                                onChange={(e) => setPostLoginWaitMs(Number(e.target.value))}
                                className={inputClass}
                              />
                            </div>
                            <div className="space-y-1.5">
                              <label className="text-[11px] font-semibold text-slate-500">Success URL contains</label>
                              <input
                                type="text"
                                placeholder="/dashboard"
                                value={successUrlContains}
                                onChange={(e) => setSuccessUrlContains(e.target.value)}
                                className={inputClass}
                              />
                            </div>
                          </div>
                        </div>
                      </details>

                      {/* ── Test Login button ── */}
                      <div className="pt-1">
                        <button
                          type="button"
                          onClick={handleTestLogin}
                          disabled={testing || !loginUrl || !authUsername || !authPassword}
                          className="flex items-center gap-2 rounded-lg border border-pink-200 bg-pink-50 px-4 py-2.5 text-xs font-bold text-pink-700 transition-all hover:bg-pink-100 hover:border-pink-300 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100"
                        >
                          {testing ? (
                            <Crosshair size={14} className="animate-spin" />
                          ) : (
                            <CheckCircle2 size={14} />
                          )}
                          {testing ? "Testing..." : "Test Login"}
                        </button>

                        {/* Test result status */}
                        <AnimatePresence>
                          {testResult.status !== "idle" && (
                            <motion.div
                              initial={{ opacity: 0, y: -4 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -4 }}
                              className={`mt-3 flex items-start gap-2 rounded-lg p-3 text-xs font-medium ${
                                testResult.status === "success"
                                  ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                                  : "bg-red-50 text-red-700 border border-red-200"
                              }`}
                            >
                              {testResult.status === "success" ? (
                                <CheckCircle2 size={16} className="shrink-0 mt-0.5" />
                              ) : (
                                <XCircle size={16} className="shrink-0 mt-0.5" />
                              )}
                              <span>{testResult.message}</span>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {error && (
        <motion.div 
          initial={{ opacity: 0, y: -10, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          className="rounded-xl bg-red-50 p-4 border border-red-100 shadow-sm"
        >
          <p className="text-[13px] font-bold text-red-600 flex items-center gap-2">
            <ShieldAlert size={18} />
            {error}
          </p>
        </motion.div>
      )}

      <button
        type="submit"
        disabled={loading}
        className="mt-8 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-rose-500 to-pink-600 px-6 py-4 text-[15px] font-bold text-white transition-all duration-300 hover:from-rose-400 hover:to-pink-500 hover:shadow-[0_8px_20px_-6px_rgba(236,72,153,0.6)] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100"
      >
        {loading ? (
          <Crosshair size={20} className="animate-spin" />
        ) : (
          <Rocket size={20} className="transition-transform group-hover:-translate-y-1 group-hover:translate-x-1" />
        )}
        {loading ? "Deploying Assets..." : "Launch Audit"}
      </button>
    </form>
  );
}

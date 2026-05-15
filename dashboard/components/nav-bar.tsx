"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import { Bell, ChevronRight, LogIn, LogOut, User } from "lucide-react";

export function NavBar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, loading, logout } = useAuth();

  const tabClass = (href: string) =>
    `rounded-full px-3 py-1.5 text-sm font-medium transition-colors ${
      pathname === href
        ? "bg-white text-slate-900 shadow-sm"
        : "text-slate-500 hover:text-slate-900 hover:bg-white/70"
    }`;

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200/80 bg-white/75 backdrop-blur-xl">
      <div className="mx-auto flex h-16 w-full max-w-7xl items-center gap-4 px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex items-center gap-3 rounded-full px-1 py-1 transition-colors hover:bg-slate-50">
          <div className="flex size-11 items-center justify-center overflow-hidden rounded-xl border border-slate-200 bg-white p-1.5 shadow-sm shadow-slate-200/60">
            <img src="/logo.png" alt="RedSentinel logo" className="block h-full w-full object-contain" />
          </div>
          {/* <div className="leading-tight">
            <div className="text-sm font-semibold tracking-wide text-slate-900">RedSentinel</div>
            <div className="text-xs text-slate-500">Security Console</div>
          </div> */}
        </Link>

        <nav className="hidden items-center gap-1 rounded-full border border-slate-200 bg-slate-50 p-1 md:flex">
          <Link href="/" className={tabClass("/")}>
            Dashboard
          </Link>
          <Link href="/activity" className={tabClass("/activity")}>
            Activity
          </Link>
          <Link href="/scans" className={tabClass("/scans")}>
            Scans
          </Link>
          <Link href="/network" className={tabClass("/network")}>
            Network
          </Link>
        </nav>

        <div className="ml-auto flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-700 sm:flex">
            <span className="size-2 rounded-full bg-emerald-500" />
            Live monitoring
          </div>

          <button className="hidden size-10 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:border-slate-300 hover:text-slate-900 sm:flex">
            <Bell size={16} />
          </button>
        </div>

        <div className="flex items-center gap-3 border-l border-slate-200 pl-3 sm:pl-4">
          {loading ? (
            <span className="text-xs text-slate-400">...</span>
          ) : user ? (
            <>
              <Link
                href="/settings"
                className="hidden items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-600 transition-colors hover:border-slate-300 hover:text-slate-900 md:flex"
              >
                <User size={13} />
                {user.name || user.email}
              </Link>

              <button
                onClick={async () => {
                  await logout();
                  router.push("/auth/login");
                }}
                className="flex items-center gap-1.5 rounded-full bg-slate-900 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-slate-700"
              >
                <LogOut size={13} />
                Logout
              </button>
            </>
          ) : (
            <>
              <Link
                href="/auth/login"
                className="flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-600 transition-colors hover:border-slate-300 hover:text-slate-900"
              >
                <LogIn size={13} />
                Login
              </Link>

              <Link
                href="/auth/register"
                className="flex items-center gap-1.5 rounded-full bg-pink-600 px-3 py-1.5 text-sm font-medium text-white shadow-sm shadow-pink-200 transition-colors hover:bg-pink-700"
              >
                Sign Up
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

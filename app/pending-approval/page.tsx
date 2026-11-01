"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/app/contexts/AuthContext";

export default function PendingApprovalPage() {
  const router = useRouter();
  const { user, profile, loading, refreshProfile, signOut } = useAuth();

  // If an admin approves this account while the user is waiting, the live
  // profile subscription updates `profile` and we move them into the app.
  useEffect(() => {
    if (profile?.is_approved || profile?.role === "admin") {
      router.replace("/");
    }
  }, [profile, router]);

  if (loading) {
    return (
      <main className="flex flex-1 items-center justify-center bg-zinc-50 px-4 py-16 dark:bg-zinc-950">
        <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>
      </main>
    );
  }

  return (
    <main className="flex flex-1 items-center justify-center bg-zinc-50 px-4 py-16 font-sans dark:bg-zinc-950">
      <div className="w-full max-w-sm text-center">
        <span className="mb-3 inline-flex h-3 w-3 rounded-full bg-amber-500" />
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-white">
          Account awaiting approval
        </h1>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          Your account{user?.email ? ` (${user.email})` : ""} was created
          successfully, but an administrator still needs to approve access to
          the network inventory.
        </p>
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
          This page updates automatically once approval is granted.
        </p>
        <div className="mt-6 flex flex-col gap-2">
          <button
            type="button"
            onClick={() => refreshProfile()}
            className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            Check again
          </button>
          <button
            type="button"
            onClick={() => signOut()}
            className="rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-200 dark:hover:bg-zinc-700"
          >
            Sign out
          </button>
        </div>
      </div>
    </main>
  );
}

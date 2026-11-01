"use client";

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Global application error:", error);
  }, [error]);

  return (
    <html lang="en">
      <body className="flex min-h-screen items-center justify-center bg-zinc-50 px-4 font-sans text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
        <div className="w-full max-w-sm text-center">
          <span className="mb-3 inline-flex h-3 w-3 rounded-full bg-red-500" />
          <h1 className="text-2xl font-semibold tracking-tight">
            The application crashed
          </h1>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            Reload the page to try again. If the problem persists, contact your
            administrator.
          </p>
          <button
            type="button"
            onClick={reset}
            className="mt-6 rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 dark:bg-white dark:text-zinc-900 dark:hover:bg-zinc-200"
          >
            Reload
          </button>
          {error.digest && (
            <p className="mt-6 font-mono text-xs text-zinc-500">
              Reference: {error.digest}
            </p>
          )}
        </div>
      </body>
    </html>
  );
}

"use client";

import { useEffect, useRef } from "react";
import { supabase } from "@/lib/supabase";

/**
 * Re-runs `onChange` whenever any of the given public tables change.
 *
 * Realtime is best-effort: if the project has not enabled the tables in the
 * `supabase_realtime` publication the subscription simply stays quiet. The
 * callback is kept in a ref so callers do not need to memoize it.
 */
export function useRealtimeRefresh(
  tables: string[],
  onChange: () => void
): void {
  const callbackRef = useRef(onChange);

  useEffect(() => {
    callbackRef.current = onChange;
  }, [onChange]);

  const key = tables.join(",");

  useEffect(() => {
    if (!key) return;

    const channel = supabase.channel(`realtime:${key}`);
    for (const table of key.split(",")) {
      channel.on(
        "postgres_changes",
        { event: "*", schema: "public", table },
        () => callbackRef.current()
      );
    }
    channel.subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [key]);
}

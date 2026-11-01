import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { supabaseUrl, supabaseAnonKey } from "@/lib/env";

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({ request });

  const supabase = createServerClient(
    supabaseUrl,
    supabaseAnonKey,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          supabaseResponse = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const url = request.nextUrl.clone();
  // Routes reachable without a session (login forms & password recovery).
  const isPublicPath =
    url.pathname === "/login" ||
    url.pathname === "/signup" ||
    url.pathname === "/forgot-password" ||
    url.pathname === "/update-password";
  // Auth landing pages: signed-in users have no business there.
  const isAuthLanding =
    url.pathname === "/login" || url.pathname === "/signup";
  // Waiting room for accounts an admin has not approved yet.
  const isPendingPath = url.pathname === "/pending-approval";

  if (!user && !isPublicPath) {
    url.pathname = "/login";
    url.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(url);
  }

  if (user && isAuthLanding) {
    url.pathname = "/";
    return NextResponse.redirect(url);
  }

  if (user && !isPublicPath) {
    // One profile lookup drives both the approval gate and the /admin role
    // guard. A missing profile is treated as unapproved (fail closed).
    const { data: profile } = await supabase
      .from("profiles")
      .select("role, is_approved")
      .eq("id", user.id)
      .maybeSingle();

    const role = profile?.role ?? "viewer";
    const approved = profile?.is_approved === true || role === "admin";

    if (!approved && !isPendingPath) {
      url.pathname = "/pending-approval";
      return NextResponse.redirect(url);
    }

    if (approved && isPendingPath) {
      url.pathname = "/";
      return NextResponse.redirect(url);
    }

    // Admin-only routes: verify the caller's profile role server-side as a
    // second layer on top of the client-side <ProtectRole> guards. RLS still
    // blocks any direct data mutation for non-admins.
    if (url.pathname.startsWith("/admin") && role !== "admin") {
      url.pathname = "/";
      return NextResponse.redirect(url);
    }
  }

  return supabaseResponse;
}
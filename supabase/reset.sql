-- ============================================================
-- FULL RESET — Butajira Polytechnic College
-- WARNING: This DELETES all application data and database objects.
-- Run this ONCE, then immediately run schema.sql, schema-rbac.sql and
-- schema-audit.sql in that order to recreate everything.
-- ============================================================

-- Views first (they depend on the tables below).
drop view if exists public.v_asset_summary;

-- Application tables (cascades remove their indexes and triggers).
drop table if exists public.audit_logs cascade;
drop table if exists public.cable_port_usage cascade;
drop table if exists public.maintenance_logs cascade;
drop table if exists public.cables cascade;
drop table if exists public.ports cascade;
drop table if exists public.assets cascade;
drop table if exists public.profiles cascade;

-- Functions and the auth signup trigger.
drop trigger if exists on_auth_user_created on auth.users;

drop function if exists public.sync_cable_port_usage() cascade;
drop function if exists public.cable_port_exclusive() cascade;
drop function if exists public.record_audit() cascade;
drop function if exists public.protect_last_admin() cascade;
drop function if exists public.is_approved() cascade;
drop function if exists public.user_role() cascade;
drop function if exists public.handle_new_user() cascade;
drop function if exists public.ensure_asset_ports(uuid) cascade;
drop function if exists public.generate_default_ports() cascade;

-- ============================================================
-- AUDIT LOGGING + HARDENING (run AFTER schema-rbac.sql)
-- 1. audit_logs table + trigger-driven change history
-- 2. Optimization indexes for the app's hottest query paths
-- 3. Port-exclusivity guard (a port can only belong to ONE active cable)
-- 4. Closes the v_asset_summary RLS bypass (security_invoker)
-- ============================================================
-- Idempotent: all statements are guarded with IF NOT EXISTS / drop+create
-- patterns and can be re-run safely on an existing install.
-- ============================================================

-- ============================================================
-- AUDIT LOGS
-- ============================================================
create table if not exists public.audit_logs (
  id         uuid primary key default gen_random_uuid(),
  table_name text not null
             check (table_name in
               ('assets', 'ports', 'cables', 'maintenance_logs', 'profiles')),
  record_id  uuid not null,
  action     text not null check (action in ('INSERT', 'UPDATE', 'DELETE')),
  changes    jsonb not null default '{}'::jsonb,
  -- Snapshot of the actor's display name so the trail stays readable even
  -- after the account is deleted (the FK below nulls actor_id on delete).
  actor_name text,
  actor_id   uuid,
  created_at timestamptz not null default now()
);

alter table public.audit_logs add column if not exists actor_name text;

-- The original schema pointed actor_id at auth.users, which PostgREST cannot
-- embed. Point it at public.profiles instead so `profiles!...` joins work,
-- while still nulling the actor when the account is removed.
alter table public.audit_logs drop constraint if exists audit_logs_actor_id_fkey;
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'audit_logs_actor_id_profiles_fkey'
      and conrelid = 'public.audit_logs'::regclass
  ) then
    alter table public.audit_logs
      add constraint audit_logs_actor_id_profiles_fkey
      foreign key (actor_id) references public.profiles(id) on delete set null;
  end if;
end $$;

alter table public.audit_logs enable row level security;

-- Only administrators may read the audit trail. There is no write policy:
-- writes happen exclusively through the trigger below (security definer),
-- and anon never receives any privilege on this table.
drop policy if exists "audit_logs_select_admin" on public.audit_logs;
create policy "audit_logs_select_admin"
  on public.audit_logs for select
  using (public.user_role() = 'admin');

-- Realtime is intentionally NOT enabled for audit_logs. The trail should
-- never leak into a broadcast channel.

-- ============================================================
-- TRIGGER FUNCTION: generic INSERT/UPDATE/DELETE audit recorder
-- ============================================================
create or replace function public.record_audit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_action text;
  v_changes jsonb;
  v_record_id uuid;
  v_actor_name text;
begin
  if tg_op = 'INSERT' then
    v_action    := 'INSERT';
    v_changes   := jsonb_build_object('new', to_jsonb(new));
    v_record_id := new.id;
  elsif tg_op = 'UPDATE' then
    v_action    := 'UPDATE';
    v_changes   := jsonb_build_object('old', to_jsonb(old), 'new', to_jsonb(new));
    v_record_id := new.id;
  else
    v_action    := 'DELETE';
    v_changes   := jsonb_build_object('old', to_jsonb(old));
    v_record_id := old.id;
  end if;

  select display_name into v_actor_name
  from public.profiles
  where id = auth.uid();

  insert into public.audit_logs
    (table_name, record_id, action, changes, actor_id, actor_name)
  values
    (tg_table_name, v_record_id, v_action, v_changes, auth.uid(), v_actor_name);

  return coalesce(new, old);
end;
$$;

-- Attach the recorder to every mutation surface.
drop trigger if exists trg_assets_audit            on public.assets;
drop trigger if exists trg_ports_audit             on public.ports;
drop trigger if exists trg_cables_audit            on public.cables;
drop trigger if exists trg_maintenance_logs_audit  on public.maintenance_logs;
drop trigger if exists trg_profiles_audit          on public.profiles;

create trigger trg_assets_audit
  after insert or update or delete on public.assets
  for each row execute function public.record_audit();

create trigger trg_ports_audit
  after insert or update or delete on public.ports
  for each row execute function public.record_audit();

create trigger trg_cables_audit
  after insert or update or delete on public.cables
  for each row execute function public.record_audit();

create trigger trg_maintenance_logs_audit
  after insert or update or delete on public.maintenance_logs
  for each row execute function public.record_audit();

create trigger trg_profiles_audit
  after insert or update or delete on public.profiles
  for each row execute function public.record_audit();

-- ============================================================
-- OPTIMIZATION INDEXES (hot query paths)
-- Foreign keys are NOT indexed automatically in PostgreSQL; these
-- indexes make FK lookups, join filters, sorting, and status counts
-- efficient as the dataset grows.
-- ============================================================
create index if not exists idx_assets_created_at   on public.assets (created_at desc);
create index if not exists idx_assets_status       on public.assets (status);
create index if not exists idx_assets_type         on public.assets (type);
create index if not exists idx_ports_asset_id      on public.ports (asset_id);
create index if not exists idx_cables_endpoint_a   on public.cables (endpoint_a_port_id);
create index if not exists idx_cables_endpoint_b   on public.cables (endpoint_b_port_id);
create index if not exists idx_cables_status       on public.cables (status);
create index if not exists idx_maintenance_asset   on public.maintenance_logs (asset_id);
create index if not exists idx_maintenance_date    on public.maintenance_logs (log_date desc);
create index if not exists idx_maintenance_type    on public.maintenance_logs (maintenance_type);
create index if not exists idx_audit_created_at    on public.audit_logs (created_at desc);
create index if not exists idx_audit_record        on public.audit_logs (record_id);
create index if not exists idx_audit_table         on public.audit_logs (table_name, created_at desc);

-- ============================================================
-- PORT EXCLUSIVITY HARDENING
-- A physical port should only map to a single ACTIVE/PLANNED cable.
-- The UI enforces this already (free-port selects); these partial
-- unique indexes make it a database invariant so decommissioned
-- cables free their ports while active/planned ones reclaim them.
-- Wrapped in a DO block so a legacy dataset that already contains
-- duplicate mappings does not fail the whole migration (an admin can
-- reconcile the data and then create the index manually). Each index is
-- created in its own block so a failure on one never rolls back the other.
do $$
begin
  create unique index if not exists uq_cables_endpoint_a_active
    on public.cables (endpoint_a_port_id)
    where status <> 'decommissioned';
exception
  when others then
    raise notice 'Skipped endpoint_a exclusivity index: duplicate active cables exist on a shared port.';
end $$;

do $$
begin
  create unique index if not exists uq_cables_endpoint_b_active
    on public.cables (endpoint_b_port_id)
    where status <> 'decommissioned';
exception
  when others then
    raise notice 'Skipped endpoint_b exclusivity index: duplicate active cables exist on a shared port.';
end $$;

-- IMPORTANT: the two unique indexes above are enforced PER ENDPOINT COLUMN,
-- which leaves a hole — a port could be used as endpoint_a in one cable and
-- as endpoint_b in another, and "mirrored" cables (A→B plus B→A) would both
-- insert. A single-row trigger that merely runs EXISTS() is NOT concurrency
-- safe (two simultaneous transactions both pass the check).
--
-- The usage table below is the real invariant: one row per port, enforced by
-- the PRIMARY KEY, so the database itself serializes conflicting writers.
create table if not exists public.cable_port_usage (
  port_id  uuid primary key references public.ports(id) on delete cascade,
  cable_id uuid not null references public.cables(id) on delete cascade
);

create index if not exists idx_cable_port_usage_cable
  on public.cable_port_usage (cable_id);

alter table public.cable_port_usage enable row level security;
revoke all on public.cable_port_usage from anon, authenticated;

create or replace function public.sync_cable_port_usage()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    delete from public.cable_port_usage where cable_id = old.id;
    return old;
  end if;

  -- Remove this cable's previous reservations, then re-reserve the ports
  -- only while the cable is active/planned. The PK on port_id makes a
  -- concurrent conflict fail instead of silently double-booking.
  delete from public.cable_port_usage where cable_id = new.id;

  if new.status <> 'decommissioned' then
    insert into public.cable_port_usage (port_id, cable_id)
    values
      (new.endpoint_a_port_id, new.id),
      (new.endpoint_b_port_id, new.id);
  end if;

  return new;
end;
$$;

drop trigger if exists trg_cables_port_exclusive on public.cables;
drop function if exists public.cable_port_exclusive();
drop trigger if exists trg_cables_port_usage on public.cables;
create trigger trg_cables_port_usage
  after insert or update or delete on public.cables
  for each row execute function public.sync_cable_port_usage();

-- Backfill reservations for existing cables. If legacy data already contains
-- duplicates we keep the earliest cable and let the app reconcile the rest.
insert into public.cable_port_usage (port_id, cable_id)
select port_id, min(cable_id)
from (
  select endpoint_a_port_id as port_id, id as cable_id
  from public.cables where status <> 'decommissioned'
  union all
  select endpoint_b_port_id as port_id, id as cable_id
  from public.cables where status <> 'decommissioned'
) used
group by port_id
on conflict (port_id) do nothing;

-- ============================================================
-- CLOSE THE v_asset_summary RLS BYPASS
-- Views execute as their owner (the superuser/service role) by default,
-- which means the view could read every row REGARDLESS of RLS. Switch it
-- to security_invoker so the caller's own policies apply, and strip anon.
-- ============================================================
alter view public.v_asset_summary set (security_invoker = on);

revoke all on public.v_asset_summary from anon;
grant select on public.v_asset_summary to authenticated;

-- ============================================================
-- ASSET TAG UNIQUENESS
-- Two devices must not share an asset tag. Empty tags are allowed (the app
-- generates one when blank). Legacy duplicates are reported, not fatal.
-- ============================================================
do $$
begin
  create unique index if not exists uq_assets_asset_tag
    on public.assets (asset_tag)
    where asset_tag <> '';
exception
  when unique_violation then
    raise notice 'Skipped asset_tag uniqueness index: duplicate tags exist. Reconcile and re-run.';
end $$;

-- ============================================================
-- REALTIME PUBLICATION
-- Let every client refresh its lists when data changes (multi-user views
-- otherwise stay stale until reload). profiles is added in schema-rbac.sql.
-- ============================================================
do $$
declare
  t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['assets', 'ports', 'cables', 'maintenance_logs'] loop
      if not exists (
        select 1 from pg_publication_tables
        where pubname = 'supabase_realtime'
          and schemaname = 'public' and tablename = t
      ) then
        execute format(
          'alter publication supabase_realtime add table public.%I', t
        );
      end if;
    end loop;
  end if;
exception
  when others then
    null;
end $$;

-- ============================================================
-- GRANTS
-- ============================================================
revoke all on public.audit_logs from anon;
grant select on public.audit_logs to authenticated;

-- Profiles mutations are enforced EXCLUSIVELY by RLS (admin-only policies).
-- Re-affirm explicit DML grants so the policy-backed path always works even
-- if the Supabase default privileges were not applied in this project.
grant select, insert, update, delete on public.profiles to authenticated;

-- ============================================================
-- USAGE NOTES
-- Verify with:
--   select table_name, count(*) from public.audit_logs group by 1;
-- View as an admin (RLS) or in the SQL editor as service_role.
-- ============================================================
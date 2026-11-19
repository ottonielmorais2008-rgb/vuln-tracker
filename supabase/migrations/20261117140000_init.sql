-- Vulnerability tracker schema, RLS, and demo-friendly auth trigger.

create schema if not exists private;

revoke all on schema private from public;
revoke all on schema private from anon, authenticated;

create table public.vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title text not null check (char_length(trim(title)) between 1 and 200),
  asset text not null check (char_length(trim(asset)) between 1 and 80),
  cve_id text null check (cve_id is null or cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  cvss numeric(3,1) not null check (cvss >= 0 and cvss <= 10),
  severity text not null check (severity in ('Critical', 'High', 'Medium', 'Low')),
  status text not null check (status in ('Open', 'In progress', 'Mitigated', 'Accepted risk')),
  owner text not null check (char_length(trim(owner)) between 1 and 80),
  due_date date null,
  notes text not null default '' check (char_length(notes) <= 4000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint severity_matches_cvss check (
    (cvss <= 3.9 and severity = 'Low')
    or (cvss >= 4.0 and cvss <= 6.9 and severity = 'Medium')
    or (cvss >= 7.0 and cvss <= 8.9 and severity = 'High')
    or (cvss >= 9.0 and severity = 'Critical')
  )
);

create index vulnerabilities_user_id_idx on public.vulnerabilities (user_id);
create index vulnerabilities_status_idx on public.vulnerabilities (user_id, status);
create index vulnerabilities_severity_idx on public.vulnerabilities (user_id, severity);

create or replace function private.touch_updated_at()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

revoke all on function private.touch_updated_at() from public;

create trigger vulnerabilities_touch_updated_at
  before update on public.vulnerabilities
  for each row
  execute function private.touch_updated_at();

-- Hosted projects confirm emails by default, and this demo has no custom SMTP.
-- Auto-confirm new users so sign-up works without an inbox. Treat this as a
-- public demo, not a verified-identity production setup.
create or replace function private.auto_confirm_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update auth.users
  set email_confirmed_at = coalesce(email_confirmed_at, now())
  where id = new.id
    and email_confirmed_at is null;
  return new;
end;
$$;

create trigger auto_confirm_user
  after insert on auth.users
  for each row
  execute function private.auto_confirm_user();

alter table public.vulnerabilities enable row level security;

create policy "users can select own vulnerabilities"
  on public.vulnerabilities for select to authenticated
  using (user_id = (select auth.uid()));

create policy "users can insert own vulnerabilities"
  on public.vulnerabilities for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "users can update own vulnerabilities"
  on public.vulnerabilities for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "users can delete own vulnerabilities"
  on public.vulnerabilities for delete to authenticated
  using (user_id = (select auth.uid()));

revoke all on public.vulnerabilities from anon;
grant select, insert, update, delete on public.vulnerabilities to authenticated;

-- Password Manager E2E sync schema. Apply in Supabase SQL editor or migration workflow.
-- The service stores ciphertext only; encrypted_payload must never contain plaintext.
create table if not exists public.password_manager_devices (
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null check (length(device_id) between 8 and 128),
  auth_session_id uuid not null,
  label text not null default 'Unnamed device' check (length(label) <= 80),
  created_at timestamptz not null default now(),
  revoked_at timestamptz null,
  primary key (user_id, device_id),
  unique (user_id, auth_session_id)
);

create table if not exists public.password_manager_vaults (
  user_id uuid not null references auth.users(id) on delete cascade,
  vault_id text not null check (length(vault_id) between 1 and 128),
  revision bigint not null default 1 check (revision > 0),
  encrypted_payload jsonb not null,
  last_device_id text not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, vault_id),
  constraint encrypted_payload_shape check (
    encrypted_payload ? 'format' and encrypted_payload->>'format' = 'password-manager-e2e-vault'
    and encrypted_payload ? 'ciphertext' and encrypted_payload ? 'nonce' and encrypted_payload ? 'salt'
    and encrypted_payload->>'revision' ~ '^[1-9][0-9]*$'
    and (encrypted_payload->>'revision') = revision::text
  )
);

alter table public.password_manager_devices enable row level security;
alter table public.password_manager_vaults enable row level security;
revoke all on public.password_manager_devices from anon;
revoke all on public.password_manager_vaults from anon;
grant select, insert, update on public.password_manager_devices to authenticated;
grant select, insert, update on public.password_manager_vaults to authenticated;

-- A session can register only itself. Revoke is one-way for authenticated clients.
drop policy if exists pm_devices_select_own on public.password_manager_devices;
create policy pm_devices_select_own on public.password_manager_devices for select to authenticated
  using (user_id = (select auth.uid()));
drop policy if exists pm_devices_insert_current_session on public.password_manager_devices;
create policy pm_devices_insert_current_session on public.password_manager_devices for insert to authenticated
  with check (user_id = (select auth.uid()) and auth_session_id = ((select auth.jwt())->>'session_id')::uuid and device_id = (coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb ->> 'x-pm-device-id') and revoked_at is null);
drop policy if exists pm_devices_revoke_only on public.password_manager_devices;
create policy pm_devices_revoke_only on public.password_manager_devices for update to authenticated
  using (user_id = (select auth.uid()) and revoked_at is null)
  with check (user_id = (select auth.uid()) and revoked_at is not null);

-- Every vault read/write requires the exact device ID header AND the session ID
-- in the verified Supabase JWT. Revoked sessions cannot use the sync table.
create or replace function public.pm_current_device_is_active()
returns boolean
language sql stable
security invoker
set search_path = ''
as $$
  select exists (
    select 1 from public.password_manager_devices d
    where d.user_id = (select auth.uid())
      and d.device_id = (coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb ->> 'x-pm-device-id')
      and d.auth_session_id = ((select auth.jwt())->>'session_id')::uuid
      and d.revoked_at is null
  );
$$;
revoke all on function public.pm_current_device_is_active() from public, anon;
grant execute on function public.pm_current_device_is_active() to authenticated;

drop policy if exists pm_vault_select_own_active_device on public.password_manager_vaults;
create policy pm_vault_select_own_active_device on public.password_manager_vaults for select to authenticated
  using (user_id = (select auth.uid()) and (select public.pm_current_device_is_active()));
drop policy if exists pm_vault_insert_own_active_device on public.password_manager_vaults;
create policy pm_vault_insert_own_active_device on public.password_manager_vaults for insert to authenticated
  with check (user_id = (select auth.uid()) and (select public.pm_current_device_is_active()) and last_device_id = (coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb ->> 'x-pm-device-id'));
drop policy if exists pm_vault_update_own_active_device on public.password_manager_vaults;
create policy pm_vault_update_own_active_device on public.password_manager_vaults for update to authenticated
  using (user_id = (select auth.uid()) and (select public.pm_current_device_is_active()))
  with check (user_id = (select auth.uid()) and (select public.pm_current_device_is_active()) and last_device_id = (coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb ->> 'x-pm-device-id'));

-- No DELETE policy is provided: accidental remote deletion is not part of normal sync.
-- The active device must use the same device_id in PM_SYNC_DEVICE_ID and the
-- x-pm-device-id header. Registering a device binds it to the current JWT session.

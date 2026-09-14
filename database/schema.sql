-- SecureMailScope Role-Based Access Control (RBAC) Schema Migration
-- Table: public.user_roles
-- Description: Maps authenticated users to authorized application roles.
-- Roles: 'SOC_ANALYST', 'EXECUTIVE'

-- 1. Create table public.user_roles
create table if not exists public.user_roles (
    user_id uuid primary key references auth.users(id) on delete cascade,
    role text not null check (role in ('SOC_ANALYST', 'EXECUTIVE')),
    created_at timestamptz default now()
);

-- 2. Enable Row Level Security (RLS)
alter table public.user_roles enable row level security;

-- 3. Policy: Authenticated users can read only their own assigned role
drop policy if exists "Users can read own role" on public.user_roles;
create policy "Users can read own role"
    on public.user_roles
    for select
    to authenticated
    using (auth.uid() = user_id);

-- 4. Security note:
-- No INSERT, UPDATE, or DELETE policies are granted to 'authenticated' or 'anon'.
-- Therefore, normal authenticated users CANNOT modify or elevate their own roles.
-- Only server-side admin operations using the service_role key or direct database
-- administration can insert or modify role assignments.

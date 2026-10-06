-- SPI Global Exchange - user management
-- Run once in the Supabase SQL editor. The last statement shows a one-time setup code;
-- enter it in the app under "User management" to choose the cockpit password.

create extension if not exists pgcrypto with schema extensions;

-- Users and their region access ('all' or region ids such as 'ams', 'buz')
create table if not exists spi_users (
  name   text primary key,
  access text[] not null default '{}',
  admin  boolean not null default false,
  sort   int not null default 0
);
alter table spi_users enable row level security;
-- Not publicly readable: the app reads users through load_spi_users() (supabase_read_protection.sql).
drop policy if exists "public read users" on spi_users;

-- Cockpit password (bcrypt hash) and the one-time setup code. No policies: not readable
-- or writable from the browser at all, only through the functions below.
create table if not exists spi_admin (
  id         int primary key default 1 check (id = 1),
  pw_hash    text,
  setup_code text
);
alter table spi_admin enable row level security;

insert into spi_users (name, access, admin, sort) values
  ('Fabio Saxer',          '{all}', true,  1),
  ('Jris Niedermann',      '{all}', false, 2),
  ('Lucia Manatschal',     '{ams}', false, 3),
  ('Yan Chen',             '{gcr}', false, 4),
  ('Sudhir Punyamurthula', '{mai}', false, 5),
  ('Roman Heuberger',      '{buz}', false, 6),
  ('Fabio Keller',         '{buz}', false, 7)
on conflict (name) do nothing;

insert into spi_admin (id, setup_code)
values (1, encode(extensions.gen_random_bytes(6), 'hex'))
on conflict (id) do nothing;

create or replace function admin_status() returns text
language sql security definer set search_path = public as $$
  select case when exists (select 1 from spi_admin where id = 1 and pw_hash is not null)
              then 'ready' else 'setup' end;
$$;

create or replace function admin_check(p_password text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare h text;
begin
  select pw_hash into h from spi_admin where id = 1;
  if h is null or p_password is null then return false; end if;
  return h = extensions.crypt(p_password, h);
end;
$$;

create or replace function admin_setup(p_code text, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare r spi_admin%rowtype;
begin
  select * into r from spi_admin where id = 1 for update;
  if r.pw_hash is not null then raise exception 'admin password already set'; end if;
  if r.setup_code is null or p_code is distinct from r.setup_code then raise exception 'wrong setup code'; end if;
  if length(coalesce(p_password, '')) < 8 then raise exception 'password too short'; end if;
  update spi_admin
     set pw_hash = extensions.crypt(p_password, extensions.gen_salt('bf', 10)), setup_code = null
   where id = 1;
end;
$$;

create or replace function admin_change_password(p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not admin_check(p_old) then raise exception 'wrong admin password'; end if;
  if length(coalesce(p_new, '')) < 8 then raise exception 'password too short'; end if;
  update spi_admin set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 10)) where id = 1;
end;
$$;

create or replace function admin_save_users(p_users jsonb, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not admin_check(p_password) then raise exception 'wrong admin password'; end if;
  if jsonb_typeof(p_users) <> 'array' or jsonb_array_length(p_users) = 0 then
    raise exception 'user list is empty';
  end if;
  if not exists (select 1 from jsonb_array_elements(p_users) u where (u->>'admin')::boolean) then
    raise exception 'at least one admin is required';
  end if;
  delete from spi_users where true;
  insert into spi_users (name, access, admin, sort)
  select trim(u->>'name'),
         coalesce(array(select jsonb_array_elements_text(u->'access')), '{}'),
         coalesce((u->>'admin')::boolean, false),
         ord
    from jsonb_array_elements(p_users) with ordinality as t(u, ord)
   where trim(coalesce(u->>'name', '')) <> '';
end;
$$;

grant execute on function admin_status() to anon;
grant execute on function admin_check(text) to anon;
grant execute on function admin_setup(text, text) to anon;
grant execute on function admin_change_password(text, text) to anon;
grant execute on function admin_save_users(jsonb, text) to anon;

-- One-time setup code for the cockpit (empty once the password is set)
select setup_code as "Setup code for the cockpit" from spi_admin where id = 1;

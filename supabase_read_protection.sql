-- SPI Global Exchange - reading only with the team password
--
-- Run once in the Supabase SQL editor AFTER the new app version is online.
-- Before running: replace TEAM-PASSWORD-HERE (one place, step 1) with the team password.
-- The password is stored only as a bcrypt hash; the app then reads data, photos and the user
-- list exclusively through the functions below, which check it server-side.

create extension if not exists pgcrypto with schema extensions;

-- 1) the team password, hashed. No policies: not readable from the browser.
create table if not exists spi_team (
  id      int primary key default 1 check (id = 1),
  pw_hash text not null
);
alter table spi_team enable row level security;
insert into spi_team (id, pw_hash)
values (1, extensions.crypt('TEAM-PASSWORD-HERE', extensions.gen_salt('bf', 8)))
on conflict (id) do update set pw_hash = excluded.pw_hash;

-- 2) password check used by every function below
create or replace function spi_pass_ok(passphrase text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from spi_team
                  where id = 1 and pw_hash = extensions.crypt(coalesce(passphrase, ''), pw_hash));
$$;

create or replace function check_spi_pass(passphrase text) returns boolean
language sql stable security definer set search_path = public as $$
  select spi_pass_ok(passphrase);
$$;

-- 3) protected reads
create or replace function load_spi_data(passphrase text) returns text
language plpgsql stable security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  return (select data from spi_data where id = 1);
end;
$$;

create or replace function spi_data_version(passphrase text) returns text
language plpgsql stable security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  return (select updated_at::text from spi_data where id = 1);
end;
$$;

create or replace function load_spi_image(p_project_id text, passphrase text) returns text
language plpgsql stable security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  return (select data_url from spi_images where project_id = p_project_id);
end;
$$;

create or replace function load_spi_users(passphrase text)
returns table(name text, access text[], admin boolean, sort int)
language plpgsql stable security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  return query select u.name, u.access, u.admin, u.sort from spi_users u order by u.sort;
end;
$$;

-- 4) writes check the hashed password too (same password as before)
create or replace function save_spi_data(new_data text, passphrase text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  update spi_data set data = new_data, updated_at = now() where id = 1;
end;
$$;

create or replace function save_spi_image(p_project_id text, p_data_url text, passphrase text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  insert into spi_images (project_id, data_url, updated_at)
  values (p_project_id, p_data_url, now())
  on conflict (project_id) do update set data_url = excluded.data_url, updated_at = now();
end;
$$;

create or replace function delete_spi_image(p_project_id text, passphrase text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not spi_pass_ok(passphrase) then raise exception 'wrong passphrase'; end if;
  delete from spi_images where project_id = p_project_id;
end;
$$;

grant execute on function check_spi_pass(text) to anon;
grant execute on function load_spi_data(text) to anon;
grant execute on function spi_data_version(text) to anon;
grant execute on function load_spi_image(text, text) to anon;
grant execute on function load_spi_users(text) to anon;
grant execute on function save_spi_data(text, text) to anon;
grant execute on function save_spi_image(text, text, text) to anon;
grant execute on function delete_spi_image(text, text) to anon;
revoke execute on function spi_pass_ok(text) from public, anon;

-- 5) close the public read access
drop policy if exists "public read access" on spi_data;
drop policy if exists "public read access images" on spi_images;
drop policy if exists "public read users" on spi_users;

-- Check: should return 0 rows for the browser (anon) from now on
-- select count(*) from spi_data;  -- (run as postgres it still shows 1, that is fine)

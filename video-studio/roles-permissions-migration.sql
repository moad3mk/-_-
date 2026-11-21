-- NEXORA permissions + multiple roles + member moderation (migration)
alter table public.profiles add column if not exists roles text[] not null default '{}';
update public.profiles set roles = array[role] where coalesce(array_length(roles,1),0)=0;

create or replace function public.has_permission(permission_key text)
returns boolean language sql stable security definer set search_path=public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id=auth.uid()
      and (
        'مالك'=any(p.roles) or p.role='مالك'
        or exists (
          select 1 from public.custom_roles r
          where r.name = any(coalesce(p.roles, array[p.role]))
            and (permission_key = any(r.permissions) or 'all'=any(r.permissions))
        )
      )
  );
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select public.has_permission('admin_access'); $$;

create or replace function public.admin_set_roles(target_user uuid, new_roles text[])
returns void language plpgsql security definer set search_path=public
as $$
declare first_role text;
begin
  if not public.has_permission('manage_roles') then raise exception 'غير مصرح بتعديل الرتب'; end if;
  if coalesce(array_length(new_roles,1),0)=0 then new_roles := array['عضو']; end if;
  if exists (
    select 1 from unnest(new_roles) n
    where n not in ('عضو','VIP','مشرف','مدير','مالك')
      and not exists(select 1 from public.custom_roles cr where cr.name=n)
  ) then raise exception 'إحدى الرتب المختارة غير موجودة'; end if;
  if 'مالك'=any(new_roles) and not exists(select 1 from public.profiles where id=auth.uid() and role='مالك') then
    raise exception 'تعيين رتبة المالك متاح للمالك الحالي فقط';
  end if;
  first_role := new_roles[1];
  update public.profiles set roles=new_roles, role=first_role where id=target_user;
end;
$$;
grant execute on function public.admin_set_roles(uuid,text[]) to authenticated;

create table if not exists public.member_moderation (
  user_id uuid primary key references auth.users(id) on delete cascade,
  banned boolean not null default false,
  timeout_until timestamptz,
  reason text default '',
  updated_at timestamptz not null default now()
);
alter table public.member_moderation enable row level security;
drop policy if exists "Admins manage moderation" on public.member_moderation;
create policy "Admins manage moderation" on public.member_moderation
for all to authenticated using (public.has_permission('ban_members') or public.has_permission('timeout_members'))
with check (public.has_permission('ban_members') or public.has_permission('timeout_members'));
drop policy if exists "Users read own moderation" on public.member_moderation;
create policy "Users read own moderation" on public.member_moderation
for select to authenticated using (auth.uid()=user_id);

create or replace function public.admin_moderate_user(target_user uuid, action text, minutes integer default null, why text default '')
returns void language plpgsql security definer set search_path=public
as $$
begin
  if action='ban' and not public.has_permission('ban_members') then raise exception 'لا تملك صلاحية حظر عضو'; end if;
  if action='timeout' and not public.has_permission('timeout_members') then raise exception 'لا تملك صلاحية التايم'; end if;
  if action='unban' and not public.has_permission('ban_members') then raise exception 'لا تملك صلاحية فك الحظر'; end if;
  if action='ban' then
    insert into public.member_moderation(user_id,banned,timeout_until,reason,updated_at)
    values(target_user,true,null,why,now())
    on conflict(user_id) do update set banned=true,timeout_until=null,reason=excluded.reason,updated_at=now();
  elsif action='timeout' then
    if minutes is null or minutes<1 or minutes>10080 then raise exception 'مدة التايم يجب أن تكون من دقيقة إلى 7 أيام'; end if;
    insert into public.member_moderation(user_id,banned,timeout_until,reason,updated_at)
    values(target_user,false,now()+make_interval(mins=>minutes),why,now())
    on conflict(user_id) do update set timeout_until=excluded.timeout_until,reason=excluded.reason,updated_at=now();
  elsif action='unban' then
    update public.member_moderation set banned=false,timeout_until=null,reason='',updated_at=now() where user_id=target_user;
  else raise exception 'إجراء غير معروف'; end if;
end;
$$;
grant execute on function public.admin_moderate_user(uuid,text,integer,text) to authenticated;

create or replace function public.enforce_chat_moderation()
returns trigger language plpgsql security definer set search_path=public
as $$
declare m public.member_moderation;
begin
  select * into m from public.member_moderation where user_id=new.sender_id;
  if coalesce(m.banned,false) then raise exception 'حسابك محظور من المحادثات'; end if;
  if m.timeout_until is not null and m.timeout_until>now() then
    raise exception 'أنت في تايم حتى %', to_char(m.timeout_until at time zone 'UTC','YYYY-MM-DD HH24:MI');
  end if;
  return new;
end;
$$;
drop trigger if exists enforce_chat_moderation_before_insert on public.messages;
create trigger enforce_chat_moderation_before_insert
before insert on public.messages for each row execute function public.enforce_chat_moderation();

drop policy if exists "Admins delete chat messages" on public.messages;
create policy "Admins delete chat messages" on public.messages
for delete to authenticated using (public.has_permission('delete_messages'));

-- Chat permissions are granted only to the selected custom role.

grant delete on public.messages to authenticated;

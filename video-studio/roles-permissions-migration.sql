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


-- إصلاح إدارة الحظر بالاسم وإضافة أوامر الدردشة المحمية
create or replace function public.admin_moderate_by_username(target_username text, action text, minutes integer default null, why text default '')
returns void language plpgsql security definer set search_path=public
as $$
declare target_id uuid;
begin
  if action='ban' and not public.has_permission('ban_members') then raise exception 'لا تملك صلاحية الحظر'; end if;
  if action='timeout' and not public.has_permission('timeout_members') then raise exception 'لا تملك صلاحية التايم'; end if;
  if action='unban' and not public.has_permission('ban_members') then raise exception 'لا تملك صلاحية فك الحظر'; end if;
  select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
  if target_id is null then raise exception 'لم نعثر على عضو بهذا الاسم'; end if;
  if target_id=auth.uid() then raise exception 'لا يمكنك تطبيق الإجراء على حسابك'; end if;
  if action='ban' then
    insert into public.member_moderation(user_id,banned,timeout_until,reason,updated_at)
    values(target_id,true,null,why,now())
    on conflict(user_id) do update set banned=true,timeout_until=null,reason=excluded.reason,updated_at=now();
  elsif action='timeout' then
    if minutes is null or minutes<1 or minutes>10080 then raise exception 'مدة التايم من دقيقة إلى 7 أيام'; end if;
    insert into public.member_moderation(user_id,banned,timeout_until,reason,updated_at)
    values(target_id,false,now()+make_interval(mins=>minutes),why,now())
    on conflict(user_id) do update set banned=false,timeout_until=excluded.timeout_until,reason=excluded.reason,updated_at=now();
  elsif action='unban' then
    update public.member_moderation set banned=false,timeout_until=null,reason='',updated_at=now() where user_id=target_id;
  else raise exception 'إجراء غير معروف'; end if;
end;
$$;
grant execute on function public.admin_moderate_by_username(text,text,integer,text) to authenticated;

create or replace function public.nexora_chat_command(cmd text, target_username text default null, role_names text[] default null, amount integer default null)
returns text language plpgsql security definer set search_path=public
as $$
declare target_id uuid; first_role text;
begin
  if cmd='owner' then
    if not exists(select 1 from public.profiles where id=auth.uid() and (role='مالك' or 'مالك'=any(roles))) then
      raise exception 'أمر /owner متاح للمالك فقط';
    end if;
    select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
    if target_id is null then raise exception 'العضو غير موجود'; end if;
    update public.profiles set role='مالك',roles=array['مالك'] where id=target_id;
    return 'تم تعيين رتبة المالك 👑';
  elsif cmd='role' then
    if not public.has_permission('manage_roles') then raise exception 'لا تملك صلاحية إدارة الرتب'; end if;
    select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
    if target_id is null then raise exception 'العضو غير موجود'; end if;
    if coalesce(array_length(role_names,1),0)=0 then raise exception 'اكتب رتبة واحدة على الأقل'; end if;
    if 'مالك'=any(role_names) and not exists(select 1 from public.profiles where id=auth.uid() and role='مالك') then raise exception 'تعيين المالك للمالك الحالي فقط'; end if;
    if exists(select 1 from unnest(role_names) n where n not in ('عضو','VIP','مشرف','مدير','مالك') and not exists(select 1 from public.custom_roles c where c.name=n)) then raise exception 'توجد رتبة غير موجودة'; end if;
    update public.profiles set roles=role_names,role=role_names[1] where id=target_id;
    return 'تم تحديث رتب العضو';
  elsif cmd='clear' then
    if not public.has_permission('delete_messages') then raise exception 'لا تملك صلاحية حذف الرسائل'; end if;
    if amount is null or amount<1 or amount>150 then raise exception 'اختر عدداً من 1 إلى 150'; end if;
    delete from public.messages where id in (select id from public.messages order by created_at desc limit amount);
    return 'تم حذف آخر '||amount||' رسالة';
  else raise exception 'أمر غير معروف'; end if;
end;
$$;
grant execute on function public.nexora_chat_command(text,text,text[],integer) to authenticated;


create or replace function public.admin_moderation_status(target_username text)
returns jsonb language plpgsql security definer set search_path=public
as $$
declare target_id uuid; m public.member_moderation;
begin
  if not (public.has_permission('ban_members') or public.has_permission('timeout_members')) then raise exception 'لا تملك صلاحية عرض حالة الحظر'; end if;
  select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
  if target_id is null then raise exception 'لم نعثر على عضو بهذا الاسم'; end if;
  select * into m from public.member_moderation where user_id=target_id;
  if not found then return jsonb_build_object('status','غير محظور'); end if;
  if m.banned then return jsonb_build_object('status','حظر دائم','reason',m.reason); end if;
  if m.timeout_until is not null and m.timeout_until>now() then return jsonb_build_object('status','تايم','until',m.timeout_until,'reason',m.reason); end if;
  return jsonb_build_object('status','غير محظور');
end;
$$;
grant execute on function public.admin_moderation_status(text) to authenticated;

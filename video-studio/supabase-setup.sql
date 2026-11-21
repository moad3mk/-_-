-- NEXORA SHOP: حسابات ورتب وطلبات مشتركة (Supabase)
-- شغّل هذا الملف مرة واحدة في Supabase > SQL Editor.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  role text not null default 'عضو' check (role in ('عضو','VIP','مشرف','مدير')),
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  customer text not null,
  product text not null,
  price numeric not null,
  game_id text not null,
  contact text not null,
  notes text default '',
  status text not null default 'جديد' check (status in ('جديد','قيد التنفيذ','مكتمل','ملغي')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.orders enable row level security;

-- إنشاء ملف العضو تلقائياً بعد التسجيل.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, username, role)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data->>'username',''), split_part(new.email,'@',1)),
    case when lower(coalesce(new.email,'')) = lower('moad000moad10@gmail.com') then 'مالك' else 'عضو' end
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- المستخدم يقرأ ملفه فقط. لا يمكنه تعديل رتبته بنفسه.
drop policy if exists "Read own profile" on public.profiles;
create policy "Read own profile" on public.profiles
for select to authenticated using (auth.uid() = id);

-- المستخدم يرسل طلباته ويقرأ طلباته فقط.
drop policy if exists "Create own orders" on public.orders;
create policy "Create own orders" on public.orders
for insert to authenticated with check (auth.uid() = user_id);

drop policy if exists "Read own orders" on public.orders;
create policy "Read own orders" on public.orders
for select to authenticated using (auth.uid() = user_id);

-- صلاحيات المدير فقط لإدارة الرتب والطلبات: تُفعّل بعد تعيين أول مدير.
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'مدير'
  );
$$;

drop policy if exists "Admin manages profiles" on public.profiles;
create policy "Admin manages profiles" on public.profiles
for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "Admin manages all orders" on public.orders;
create policy "Admin manages all orders" on public.orders
for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- بعد إنشاء حسابك من الموقع، نفّذ هذا السطر مرة واحدة مع استبدال البريد:
-- update public.profiles p set role = 'مدير'
-- from auth.users u where p.id = u.id and u.email = 'YOUR_EMAIL_HERE';

-- إضافات الملف الشخصي والدردشة العامة (شغّل هذا الجزء بعد الإعداد الأساسي)
alter table public.profiles add column if not exists avatar_url text;
drop policy if exists "Update own profile" on public.profiles;
create policy "Update own profile" on public.profiles
for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

create table if not exists public.messages (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references auth.users(id) on delete cascade,
 sender_name text not null,
 sender_avatar text,
 content text not null check (char_length(content) between 1 and 1500),
 created_at timestamptz not null default now()
);
alter table public.messages enable row level security;
drop policy if exists "Authenticated users read messages" on public.messages;
create policy "Authenticated users read messages" on public.messages
for select to authenticated using (true);
drop policy if exists "Users send own messages" on public.messages;
create policy "Users send own messages" on public.messages
for insert to authenticated with check (auth.uid() = sender_id);

insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('avatars','avatars',true,3145728,array['image/jpeg','image/png','image/webp','image/gif'])
on conflict (id) do update set public=true,file_size_limit=3145728,allowed_mime_types=array['image/jpeg','image/png','image/webp','image/gif'];
drop policy if exists "Avatar images are public" on storage.objects;
create policy "Avatar images are public" on storage.objects for select using (bucket_id='avatars');
drop policy if exists "Users upload own avatar" on storage.objects;
create policy "Users upload own avatar" on storage.objects for insert to authenticated
with check (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "Users update own avatar" on storage.objects;
create policy "Users update own avatar" on storage.objects for update to authenticated
using (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text)
with check (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);

-- السماح بتعديل الاسم والصورة فقط ومنع العضو من تغيير رتبته
revoke update on public.profiles from authenticated;
grant update (username, avatar_url) on public.profiles to authenticated;


create or replace function public.admin_set_role(target_user uuid, new_role text)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_admin() then raise exception 'غير مصرح'; end if;
 if new_role not in ('عضو','VIP','مشرف','مدير') then raise exception 'رتبة غير صالحة'; end if;
 update public.profiles set role=new_role where id=target_user;
end;
$$;
grant execute on function public.admin_set_role(uuid,text) to authenticated;

-- تفعيل التحديث الفوري للرسائل في صفحة الدردشة
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

 
-- نظام الرتب المخصصة: اسم + لون + أيقونة + صلاحيات
do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
    where conrelid='public.profiles'::regclass and contype='c'
      and pg_get_constraintdef(oid) ilike '%role%'
  loop
    execute format('alter table public.profiles drop constraint %I', c.conname);
  end loop;
end $$;

create table if not exists public.custom_roles (
  name text primary key,
  icon text not null default '🏷️',
  color text not null default '#8b5cf6',
  permissions text[] not null default '{}',
  created_at timestamptz not null default now()
);
alter table public.custom_roles enable row level security;
drop policy if exists "Authenticated users read custom roles" on public.custom_roles;
create policy "Authenticated users read custom roles" on public.custom_roles
for select to authenticated using (true);
drop policy if exists "Admins manage custom roles" on public.custom_roles;
create policy "Admins manage custom roles" on public.custom_roles
for all to authenticated using (public.is_admin()) with check (public.is_admin());
grant select, insert, update, delete on public.custom_roles to authenticated;

create or replace function public.admin_set_role(target_user uuid, new_role text)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_admin() then raise exception 'غير مصرح'; end if;
 if new_role not in ('عضو','VIP','مشرف','مدير')
    and not exists (select 1 from public.custom_roles where name=new_role) then
   raise exception 'الرتبة غير موجودة';
 end if;
 update public.profiles set role=new_role where id=target_user;
end;
$$;
grant execute on function public.admin_set_role(uuid,text) to authenticated;


-- رتبة المالك للحساب المحدد
insert into public.custom_roles (name, icon, color, permissions)
values ('مالك', '👑', '#f5c542', array['all'])
on conflict (name) do update
set icon=excluded.icon, color=excluded.color, permissions=excluded.permissions;

-- إذا كان الحساب مسجلاً بالفعل، تُعيّن له رتبة مالك مباشرة
update public.profiles p
set role = 'مالك'
from auth.users u
where p.id = u.id
  and lower(u.email) = lower('moad000moad10@gmail.com');


-- إظهار رتبة المرسل في الدردشة، مع أخذها من ملفه تلقائياً لمنع تزويرها
alter table public.messages add column if not exists sender_role text;
create or replace function public.set_message_sender_role()
returns trigger language plpgsql security definer set search_path=public
as $$
begin
  select role into new.sender_role from public.profiles where id = new.sender_id;
  return new;
end;
$$;
drop trigger if exists set_message_sender_role_before_insert on public.messages;
create trigger set_message_sender_role_before_insert
before insert on public.messages
for each row execute function public.set_message_sender_role();


-- رتبة المالك لها صلاحيات الإدارة أيضاً.
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('مدير', 'مالك')
  );
$$;


-- إصلاح رتبة المالك للحساب الموجود، وكذلك تعيينها تلقائياً للحساب عند التسجيل
update public.profiles p
set role = 'مالك'
from auth.users u
where p.id = u.id
  and lower(coalesce(u.email,'')) = lower('moad000moad10@gmail.com');


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


-- إصلاح صلاحيات إرسال الرسائل وتوسيع أوامر الشات
grant select, insert, delete on public.messages to authenticated;
drop policy if exists "Users send own messages" on public.messages;
create policy "Users send own messages" on public.messages
for insert to authenticated with check (auth.uid() = sender_id);
drop policy if exists "Authenticated users read messages" on public.messages;
create policy "Authenticated users read messages" on public.messages
for select to authenticated using (true);

create or replace function public.nexora_chat_command(cmd text, target_username text default null, role_names text[] default null, amount integer default null)
returns text language plpgsql security definer set search_path=public
as $$
declare target_id uuid;
begin
  if cmd='owner' then
    if not exists(select 1 from public.profiles where id=auth.uid() and (role='مالك' or 'مالك'=any(roles))) then
      raise exception 'أمر /owner متاح للمالك فقط';
    end if;
    select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
    if target_id is null then raise exception 'العضو غير موجود'; end if;
    if target_id=auth.uid() then raise exception 'أنت مالك بالفعل'; end if;
    update public.profiles set role='مالك',roles=array['مالك'] where id=target_id;
    return 'تم تعيين رتبة المالك للعضو 👑';
  elsif cmd='role' then
    if not public.has_permission('manage_roles') then raise exception 'لا تملك صلاحية إدارة الرتب'; end if;
    select id into target_id from public.profiles where lower(username)=lower(trim(target_username)) limit 1;
    if target_id is null then raise exception 'العضو غير موجود'; end if;
    if coalesce(array_length(role_names,1),0)=0 then raise exception 'اكتب رتبة واحدة على الأقل'; end if;
    if 'مالك'=any(role_names) and not exists(select 1 from public.profiles where id=auth.uid() and (role='مالك' or 'مالك'=any(roles))) then raise exception 'تعيين المالك للمالك الحالي فقط'; end if;
    if exists(select 1 from unnest(role_names) n where n not in ('عضو','VIP','مشرف','مدير','مالك') and not exists(select 1 from public.custom_roles c where c.name=n)) then raise exception 'توجد رتبة غير موجودة'; end if;
    update public.profiles set roles=role_names,role=role_names[1] where id=target_id;
    return 'تم تحديث رتب العضو';
  elsif cmd='ban' then
    perform public.admin_moderate_by_username(target_username,'ban',null,'حظر من أمر الشات');
    return 'تم حظر العضو نهائياً من الدردشة';
  elsif cmd='timeout' then
    perform public.admin_moderate_by_username(target_username,'timeout',amount,'تايم من أمر الشات');
    return 'تم تطبيق التايم على العضو';
  elsif cmd='unban' then
    perform public.admin_moderate_by_username(target_username,'unban',null,'');
    return 'تم فك الحظر أو التايم عن العضو';
  elsif cmd='clear' then
    if not public.has_permission('delete_messages') then raise exception 'لا تملك صلاحية حذف الرسائل'; end if;
    if amount is null or amount<1 or amount>150 then raise exception 'اختر عدداً من 1 إلى 150'; end if;
    delete from public.messages where id in (select id from public.messages order by created_at desc limit amount);
    return 'تم حذف آخر '||amount||' رسالة';
  else raise exception 'أمر غير معروف'; end if;
end;
$$;
grant execute on function public.nexora_chat_command(text,text,text[],integer) to authenticated;

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
  insert into public.profiles (id, username)
  values (new.id, coalesce(nullif(new.raw_user_meta_data->>'username',''), split_part(new.email,'@',1)));
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

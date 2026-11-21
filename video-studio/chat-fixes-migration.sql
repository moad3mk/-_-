-- NEXORA chat fixes: message schema, moderation by username, slash commands
alter table public.messages add column if not exists sender_role text;

create or replace function public.admin_moderate_by_username(target_username text, action text, minutes integer default null, why text default '')
returns void language plpgsql security definer set search_path=public
as $$
declare target_id uuid;
begin
  select id into target_id
  from public.profiles
  where lower(trim(username))=lower(trim(target_username))
  order by created_at asc
  limit 1;
  if target_id is null then raise exception 'لم نعثر على عضو بهذا الاسم'; end if;
  perform public.admin_moderate_user(target_id, action, minutes, why);
end;
$$;
grant execute on function public.admin_moderate_by_username(text,text,integer,text) to authenticated;

create table profiles (id uuid primary key, email text, is_admin boolean default false);
alter table profiles disable row level security;

create table posts (id serial primary key, author uuid, body text);
alter table posts enable row level security;
create policy "todos podem tudo" on posts for all using (true);

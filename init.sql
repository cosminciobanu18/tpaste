CREATE ROLE tpaste_user LOGIN PASSWORD 'rust';
CREATE DATABASE tpaste_db OWNER tpaste_user;

\connect tpaste_db

CREATE TABLE users (
    id serial primary key not null,
    username varchar(40) not null unique,
    email varchar(64) not null unique,
    hashed_password text not null,
    created_at timestamp default now() not null
);
CREATE TABLE pastes (
    id serial primary key not null,
    title varchar(70) not null,
    content text not null,
    user_id integer not null,
    url text not null,
    created_at timestamp default now() not null,
    constraint fk_user foreign key (user_id) references users(id)
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO tpaste_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO tpaste_user;


-- Two soft-deleted personal-data tables whose names both read "a.b.c":
-- table "b.c" in schema "a", and table "c" in schema "a.b".
CREATE SCHEMA a;
CREATE SCHEMA "a.b";
CREATE TABLE a."b.c" (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);
CREATE TABLE "a.b".c (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);

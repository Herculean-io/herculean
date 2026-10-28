-- dblink and postgres_fdw installed, with no foreign table: calls through
-- them can reach other databases but leave nothing in this catalog to read.
CREATE EXTENSION dblink;
CREATE EXTENSION postgres_fdw;
CREATE TABLE customers (
    id    bigserial PRIMARY KEY,
    email text NOT NULL
);

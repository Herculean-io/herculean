-- Columns whose name-based classification an engineer overrides in data-map.yaml.
CREATE TABLE customers (
    id        bigserial PRIMARY KEY,
    email     text NOT NULL,
    full_name text NOT NULL,
    notes     text
);
CREATE TABLE vendors (
    id   bigserial PRIMARY KEY,
    name text NOT NULL
);

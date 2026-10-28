-- Customers are purged by src/purge.rs; orders hold no personal data yet.
CREATE TABLE customers (
    id    bigint PRIMARY KEY,
    email text NOT NULL
);

CREATE TABLE orders (
    id    bigint PRIMARY KEY,
    total numeric(10, 2) NOT NULL
);

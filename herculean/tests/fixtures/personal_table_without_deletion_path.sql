-- One table of personal data with no deletion path, plus one non-personal table.
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    full_name  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO customers (email, full_name) VALUES
    ('zelda.quixote@rowvalue.test', 'Zelda Quixote'),
    ('barnaby.fizzwick@rowvalue.test', 'Barnaby Fizzwick');

CREATE TABLE products (
    id    bigserial PRIMARY KEY,
    sku   text NOT NULL,
    price numeric(10, 2) NOT NULL
);
INSERT INTO products (sku, price) VALUES ('SKU-XYZZY-9931', 12.34);

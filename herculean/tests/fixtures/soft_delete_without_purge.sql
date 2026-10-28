-- Personal data soft-deleted via deleted_at, with no purge job to remove the rows.
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    deleted_at timestamptz
);
INSERT INTO customers (email, deleted_at) VALUES ('ophelia.wrenfold@rowvalue.test', now());

-- A trigger that copies personal data into a history table on every change.
-- ON DELETE CASCADE gives both personal tables a deletion path, isolating the flow.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);
CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    email      text NOT NULL,
    account_id bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE
);
CREATE TABLE customers_history (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL,
    email       text NOT NULL,
    account_id  bigint NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    changed_at  timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION customers_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    Insert Into public.customers_history (customer_id, email, account_id)
    VALUES (OLD.id, OLD.email, OLD.account_id);
    RETURN NEW;
END
$$;
CREATE TRIGGER customers_audit AFTER UPDATE OR DELETE ON customers
    FOR EACH ROW EXECUTE FUNCTION customers_audit();

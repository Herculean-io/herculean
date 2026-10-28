-- Managed-service export channels, stubbed: no real pg_net, Supabase or aws_s3.
-- A webhook trigger calling net.http_post and a Supabase Database Webhook
-- (function in supabase_functions) on a personal table; the same webhook on a
-- table with no personal data; an aws_s3 row in pg_extension.
CREATE SCHEMA net;
CREATE FUNCTION net.http_post(url text, body jsonb) RETURNS bigint
    LANGUAGE sql AS 'SELECT 1::bigint';
CREATE SCHEMA supabase_functions;
CREATE FUNCTION supabase_functions.http_request() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE FUNCTION notify_crm() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM Net.Http_Post('https://crm.example.com/hook', to_jsonb(NEW));
    RETURN NEW;
END
$$;
CREATE TABLE customers (
    id    bigserial PRIMARY KEY,
    email text NOT NULL
);
CREATE TABLE plans (
    id   bigserial PRIMARY KEY,
    tier text NOT NULL
);
CREATE TRIGGER customers_crm AFTER INSERT ON customers
    FOR EACH ROW EXECUTE FUNCTION notify_crm();
CREATE TRIGGER customers_webhook AFTER INSERT ON customers
    FOR EACH ROW EXECUTE FUNCTION supabase_functions.http_request('https://hooks.example.com', 'POST');
CREATE TRIGGER plans_crm AFTER INSERT ON plans
    FOR EACH ROW EXECUTE FUNCTION notify_crm();
-- ponytail: a catalog row, not a real extension; the scan only reads extname.
INSERT INTO pg_catalog.pg_extension (oid, extname, extowner, extnamespace, extrelocatable, extversion)
VALUES (999999, 'aws_s3', 10, 2200, false, '1.0');

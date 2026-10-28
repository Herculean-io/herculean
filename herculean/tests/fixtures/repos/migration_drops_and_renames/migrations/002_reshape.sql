-- Later schema changes: each must be applied to the repo facts, in order.
ALTER TABLE customers DROP COLUMN phone;
ALTER TABLE customers RENAME COLUMN mail TO email;
ALTER TABLE customers RENAME TO clients;
ALTER TABLE clients DROP CONSTRAINT customers_account_id_fkey;
ALTER TABLE clients
    ADD CONSTRAINT clients_account_id_fkey FOREIGN KEY (account_id)
    REFERENCES accounts (id) ON DELETE CASCADE;
DROP TABLE temp_imports;

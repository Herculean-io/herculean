-- Delete rules added after the tables: both are deletion paths (a cascade; SET NULL would not be).
ALTER TABLE customers
    ADD CONSTRAINT customers_account_id_fkey FOREIGN KEY (account_id)
    REFERENCES accounts (id) ON DELETE CASCADE;

ALTER TABLE contacts
    ADD FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE;

ALTER TABLE customers
    ADD CONSTRAINT customers_account_id_fkey FOREIGN KEY (account_id)
    REFERENCES accounts (id) ON DELETE CASCADE;

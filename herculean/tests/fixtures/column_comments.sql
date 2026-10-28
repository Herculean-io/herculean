-- Columns whose names say nothing, but whose comments do.
CREATE TABLE members (
    id             bigserial PRIMARY KEY,
    contact_handle text,
    born           date,
    full_name      text,
    tax_ref        text,
    remarks        text
);
COMMENT ON COLUMN members.contact_handle IS 'Customer E-mail? no: customer email for receipts';
COMMENT ON COLUMN members.born IS 'Date of Birth, as entered at signup';
COMMENT ON COLUMN members.full_name IS 'email of the account owner';
COMMENT ON COLUMN public.members.tax_ref IS 'Contains PII';
COMMENT ON COLUMN members.remarks IS 'Internal remarks';

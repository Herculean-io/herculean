-- The column names real schemas use: whole words split on `_`, camelCase and digits.
-- `patients` has one column per name rule and one per health comment keyword;
-- `records` holds the look-alikes that must not classify.
-- Same text as repos/column_name_tokens/migrations/001_schema.sql.
CREATE TABLE patients (
    id                    bigserial PRIMARY KEY,
    user_email            text,
    "phoneNumber"         text,
    "firstName"           text,
    phone2                text,
    ssn                   text,
    dob                   date,
    birth_date            date,
    birthdate             date,
    birthday              date,
    postal_code           text,
    zip                   text,
    zipcode               text,
    postcode              text,
    diagnosis             text,
    icd10_code            text,
    mrn                   text,
    medical_record_number text,
    medication            text,
    prescription          text,
    last_lab_result       text,
    insurance_member_id   text,
    chart                 text,
    history               text,
    notes                 text,
    status                text,
    allergies             text,
    pregnant              boolean
);
COMMENT ON COLUMN patients.chart IS 'PHI';
COMMENT ON COLUMN patients.history IS 'Medical history';
COMMENT ON COLUMN patients.notes IS 'Latest diagnosis, free text';
COMMENT ON COLUMN patients.status IS 'Health status';
COMMENT ON COLUMN patients.allergies IS 'Food allergy list';
COMMENT ON COLUMN patients.pregnant IS 'health flag';

CREATE TABLE records (
    id              bigserial PRIMARY KEY,
    file_name       text,
    "fileName"      text,
    product_name    text,
    email           boolean,
    has_phone       boolean,
    email_verified_at timestamptz,
    phone_grace     interval,
    order_condition text,
    allergy         text,
    zipper          text,
    conditions      text
);
COMMENT ON COLUMN records.conditions IS 'Current condition of the patient';
ALTER TABLE records RENAME COLUMN has_phone TO phone;

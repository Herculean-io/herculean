-- Text columns whose values look numeric but are not phone numbers: dates, ids, IPs, decimals.
CREATE TABLE events (
    id         bigserial PRIMARY KEY,
    happened   text,
    ref_code   text,
    host       text,
    amount     text
);
INSERT INTO events (happened, ref_code, host, amount) VALUES
    ('2024-01-15', '48213377051', '192.168.10.24', '12345.67'),
    ('2023-11-02', '90017733412', '10.20.30.40', '99881.05'),
    ('2025-06-30', '55120098431', '172.16.254.1', '31415.92');

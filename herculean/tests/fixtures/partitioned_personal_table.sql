-- A partitioned table of personal data: the parent stands for its partitions.
CREATE TABLE customers (
    id    bigint NOT NULL,
    email text NOT NULL
) PARTITION BY RANGE (id);
CREATE TABLE customers_low PARTITION OF customers FOR VALUES FROM (0) TO (1000);
CREATE TABLE customers_high PARTITION OF customers FOR VALUES FROM (1000) TO (MAXVALUE);

-- A text column whose name says nothing, but whose values are email addresses.
CREATE TABLE leads (
    id      bigserial PRIMARY KEY,
    email   text NOT NULL,
    reach   text,
    memo    text,
    score   int
);
INSERT INTO leads (email, reach, memo, score) VALUES
    ('known.one@rowvalue.test', 'quentin.marlowe@samplevalue.test', 'call back Tuesday', 3),
    ('known.two@rowvalue.test', 'ysolde.brack@samplevalue.test', 'prefers mornings', 5),
    ('known.three@rowvalue.test', '+44 20 7946 0958', NULL, 1);

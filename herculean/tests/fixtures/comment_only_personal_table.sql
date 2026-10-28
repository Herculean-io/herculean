-- The live side of repos/comment_only_personal_table: the comment-classified table was never created.
CREATE TABLE accounts (
    id   bigserial PRIMARY KEY,
    plan text NOT NULL
);

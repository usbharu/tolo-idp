CREATE TABLE idp_relation_membership_cache (
    tenant_id varchar(100) NOT NULL,
    user_id varchar(200) NOT NULL,
    payload clob NOT NULL,
    cached_at timestamp NOT NULL,
    expires_at timestamp NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX ix_relation_membership_cache_expires_at ON idp_relation_membership_cache (expires_at);
